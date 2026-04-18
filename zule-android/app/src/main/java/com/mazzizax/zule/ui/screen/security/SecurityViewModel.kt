package com.mazzizax.zule.ui.screen.security

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.OrphanedPasskeyException
import com.mazzizax.zule.data.repository.PasskeyRepository
import com.mazzizax.zule.domain.model.Passkey
import com.mazzizax.zule.util.DeviceFlags
import com.mazzizax.zule.util.PwnedPasswordException
import com.mazzizax.zule.util.PwnedPasswords
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Translation of Security.tsx state management.
 *
 * Web app state:
 *   newPassword: string
 *   confirmPassword: string
 *   changingPassword: boolean
 *   error: string | null
 *   success: string | null
 *   passkeys: Passkey[]
 *   loadingPasskeys: boolean
 *   registeringPasskey: boolean
 *   deletingPasskeyId: string | null
 *   deleting: boolean (account deletion)
 *
 * Web app actions:
 *   handleChangePassword() → supabase.auth.updateUser({ password })
 *   handleRegisterPasskey() → registerPasskey(user.id, user.email, undefined)
 *   handleDeletePasskey(id) → deletePasskey(id)
 *   handleSignOutAllDevices() → supabase.auth.signOut({ scope: 'global' })
 *   handleDeleteAccount() → POST /functions/v1/delete-account then signOut
 *   loadPasskeys() → listPasskeys()
 */
data class SecurityUiState(
    val newPassword: String = "",
    val confirmPassword: String = "",
    val isChangingPassword: Boolean = false,
    val passkeys: List<Passkey> = emptyList(),
    val isLoadingPasskeys: Boolean = true,
    val isRegisteringPasskey: Boolean = false,
    val deletingPasskeyId: String? = null,
    val isDeletingAccount: Boolean = false,
    val email: String? = null,
    val createdAt: String? = null,
    val lastSignInAt: String? = null,
    val error: String? = null,
    val success: String? = null,
)

@HiltViewModel
class SecurityViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val authRepository: AuthRepository,
    private val passkeyRepository: PasskeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SecurityUiState())
    val uiState: StateFlow<SecurityUiState> = _uiState.asStateFlow()

    init {
        loadUserInfo()
        loadPasskeys()
    }

    private fun loadUserInfo() {
        val user = authRepository.currentUser()
        _uiState.update {
            it.copy(
                email = user?.email,
                createdAt = user?.createdAt?.toString(),
                lastSignInAt = user?.lastSignInAt?.toString(),
            )
        }
    }

    private fun loadPasskeys() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoadingPasskeys = true) }
            passkeyRepository.listPasskeys()
                .onSuccess { passkeys ->
                    _uiState.update { it.copy(passkeys = passkeys, isLoadingPasskeys = false) }
                }
                .onFailure {
                    _uiState.update { it.copy(isLoadingPasskeys = false) }
                }
        }
    }

    fun onNewPasswordChange(value: String) {
        _uiState.update { it.copy(newPassword = value, error = null, success = null) }
    }

    fun onConfirmPasswordChange(value: String) {
        _uiState.update { it.copy(confirmPassword = value, error = null, success = null) }
    }

    fun updatePassword() {
        val state = _uiState.value

        if (state.newPassword != state.confirmPassword) {
            _uiState.update { it.copy(error = "New passwords do not match") }
            return
        }
        // 12-char minimum matches zule's server-side config.toml policy and the
        // register / recovery flows. Any password change path below 12 chars
        // would be rejected by the server anyway.
        if (state.newPassword.length < 12) {
            _uiState.update { it.copy(error = "Password must be at least 12 characters") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isChangingPassword = true, error = null, success = null) }
            try {
                // HIBP k-anonymity breach check. Same gate as register and
                // forgot-password; was missing here. Fail-open on network.
                val hibp = PwnedPasswords.check(state.newPassword)
                if (hibp is PwnedPasswords.Result.Pwned) {
                    throw PwnedPasswordException(hibp.breachCount)
                }

                authRepository.updatePassword(state.newPassword)
                _uiState.update {
                    it.copy(
                        isChangingPassword = false,
                        newPassword = "",
                        confirmPassword = "",
                        success = "Password updated successfully",
                    )
                }
            } catch (e: Throwable) {
                _uiState.update {
                    it.copy(
                        isChangingPassword = false,
                        error = when (e) {
                            is PwnedPasswordException ->
                                "Pick a different password — this one appears in ${e.breachCount} known breaches."
                            else -> "Failed to update password"
                        },
                    )
                }
            }
        }
    }

    /**
     * Translation of Security.tsx handleRegisterPasskey:
     *   setRegisteringPasskey(true)
     *   const result = await registerPasskey(user.id, user.email, undefined)
     *   if (result.success) { setSuccess(...); await loadPasskeys() }
     *   else { setError(result.error) }
     *   setRegisteringPasskey(false)
     *
     * registerPasskey() in webauthn.ts:
     *   1. GET passkey-register?action=options → server options + challenge_key
     *   2. navigator.credentials.create({ publicKey: options }) → attestation
     *   3. POST passkey-register with challenge_key + response + device_name
     *
     * Android translation:
     *   1. passkeyRepository.getRegistrationOptions() → options JSON + challenge_key
     *   2. CredentialManager.createCredential(activity, CreatePublicKeyCredentialRequest(optionsJson))
     *   3. passkeyRepository.registerPasskey(challengeKey, responseJson, deviceName)
     */
    fun registerPasskey(activity: android.app.Activity) {
        viewModelScope.launch {
            _uiState.update { it.copy(isRegisteringPasskey = true, error = null, success = null) }
            try {
                // Strict server-driven enrollment via passkey-register-begin /
                // passkey-register-finish. Options: platform authenticator
                // required, resident key required, UV required. Step A/B split
                // with OrphanedPasskeyException so a Credential-Manager success
                // followed by a server-finish failure surfaces as a retry-
                // oriented state instead of a silent orphan in GPM.
                passkeyRepository.enrollPasskeyStrict(activity)

                // Mark this device as having an enrolled passkey so the
                // login screen can collapse to the single passkey button.
                DeviceFlags.markPasskeyEnrolled(appContext)

                _uiState.update { it.copy(
                    isRegisteringPasskey = false,
                    success = "Passkey registered successfully! You can now use biometrics to sign in.",
                ) }
                loadPasskeys()
            } catch (t: Throwable) {
                _uiState.update { it.copy(
                    isRegisteringPasskey = false,
                    error = when {
                        t is OrphanedPasskeyException ->
                            "Passkey was created on this device but we couldn't save it to the server. Try again — we'll overwrite the orphan."
                        t.message?.contains("cancelled", ignoreCase = true) == true ||
                        t.message?.contains("canceled", ignoreCase = true) == true ->
                            "Registration was cancelled or not allowed"
                        else -> t.message ?: "Failed to register passkey"
                    },
                ) }
            }
        }
    }

    fun onPasskeyRegistered() {
        _uiState.update { it.copy(
            isRegisteringPasskey = false,
            success = "Passkey registered successfully! You can now use biometrics to sign in.",
        ) }
        loadPasskeys()
    }

    fun onPasskeyRegistrationFailed(message: String) {
        _uiState.update { it.copy(
            isRegisteringPasskey = false,
            error = message,
        ) }
    }

    fun deletePasskey(passkeyId: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(deletingPasskeyId = passkeyId, error = null) }
            passkeyRepository.deletePasskey(passkeyId)
                .onSuccess {
                    // We don't have a stable credential_id ↔ this-device
                    // mapping, so clear the flag on every delete. Next
                    // sign-in will re-mark it if a passkey still works.
                    DeviceFlags.clearPasskeyEnrolled(appContext)
                    _uiState.update { it.copy(
                        deletingPasskeyId = null,
                        success = "Passkey removed",
                    ) }
                    loadPasskeys()
                }
                .onFailure {
                    _uiState.update { it.copy(
                        deletingPasskeyId = null,
                        error = "Failed to remove passkey",
                    ) }
                }
        }
    }

    fun signOutAllDevices(onComplete: () -> Unit) {
        viewModelScope.launch {
            try {
                authRepository.signOutGlobal()
            } catch (_: Exception) {
                // Best-effort
            }
            // Global sign-out invalidates every session including this one;
            // the user will need to re-authenticate with password next.
            DeviceFlags.clearPasskeyEnrolled(appContext)
            onComplete()
        }
    }

    fun deleteAccount(onComplete: () -> Unit) {
        viewModelScope.launch {
            _uiState.update { it.copy(isDeletingAccount = true, error = null) }
            authRepository.deleteAccount()
                .onSuccess {
                    DeviceFlags.clearPasskeyEnrolled(appContext)
                    onComplete()
                }
                .onFailure {
                    _uiState.update { it.copy(
                        isDeletingAccount = false,
                        error = "Failed to delete account",
                    ) }
                }
        }
    }
}

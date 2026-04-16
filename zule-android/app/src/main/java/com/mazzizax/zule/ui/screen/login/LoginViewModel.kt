package com.mazzizax.zule.ui.screen.login

import android.app.Activity
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.PasskeyRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Translation of Login.tsx state and handlers.
 *
 * Web app state:
 *   email, password, loading, passkeyLoading, error
 *   webAuthnSupported, platformAuthAvailable
 *   callbackUrl, appId (from URL search params)
 *
 * Web app handlers:
 *   handleSubmit: validate non-empty, signIn(email, password), navigate
 *   handlePasskeyLogin: authenticateWithPasskey(), if callback redirect, else show message
 *
 * On Android there are no URL search params — no callback URL.
 * The web app itself says: "Passkey verified, but no callback URL provided.
 * Please use email/password to sign in to the dashboard."
 * So the passkey button triggers Credential Manager but does not create a session.
 */

data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val passkeyLoading: Boolean = false,
    val error: String? = null,
)

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    private val passkeyRepository: PasskeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    fun onEmailChange(email: String) {
        _uiState.update { it.copy(email = email, error = null) }
    }

    fun onPasswordChange(password: String) {
        _uiState.update { it.copy(password = password, error = null) }
    }

    /**
     * Translation of handleSubmit from Login.tsx:
     *   if (!email || !password) setError('Please enter email and password')
     *   await signIn(email, password)
     *   navigate(returnTo || '/')
     */
    fun signIn(onSuccess: () -> Unit) {
        val state = _uiState.value

        if (state.email.isBlank() || state.password.isBlank()) {
            _uiState.update { it.copy(error = "Please enter email and password") }
            return
        }

        _uiState.update { it.copy(isLoading = true, error = null) }

        viewModelScope.launch {
            try {
                authRepository.signIn(state.email.trim(), state.password)
                onSuccess()
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = e.message ?: "Invalid credentials",
                    )
                }
            }
        }
    }

    /**
     * Translation of handlePasskeyLogin from Login.tsx:
     *   setPasskeyLoading(true)
     *   setError(null)
     *   const result = await authenticateWithPasskey()
     *   if (result.success && result.userId) {
     *     if (callbackUrl) { redirect } — no callback on Android
     *     else { setError('Passkey verified, but no callback URL...') }
     *   } else { setError(result.error) }
     *
     * Android equivalent: Credential Manager getCredential() triggers system passkey UI.
     * Since there's no callback URL on the mobile login screen, this matches the web's
     * "no callback" branch — passkey doesn't create a Supabase session.
     */
    fun signInWithPasskey(activity: Activity) {
        _uiState.update { it.copy(passkeyLoading = true, error = null) }

        viewModelScope.launch {
            try {
                val credentialManager = CredentialManager.create(activity)

                // Build a discoverable credential request matching webauthn.ts authenticateWithPasskey()
                // rpId = window.location.hostname → zule.mazzizax.net (from webauthn-config.ts)
                // userVerification = 'preferred'
                // timeout = 120000
                val challengeJson = """
                    {
                        "challenge": "${generateBase64Challenge()}",
                        "rpId": "zule.mazzizax.net",
                        "userVerification": "preferred",
                        "timeout": 120000
                    }
                """.trimIndent()

                val option = GetPublicKeyCredentialOption(requestJson = challengeJson)
                val request = GetCredentialRequest(listOf(option))

                val response = credentialManager.getCredential(activity, request)
                val credential = response.credential

                if (credential is PublicKeyCredential) {
                    // Passkey verified, but no callback URL — matches web behavior exactly
                    _uiState.update {
                        it.copy(
                            passkeyLoading = false,
                            error = "Passkey verified, but no callback URL provided. Please use email/password to sign in to the dashboard.",
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            passkeyLoading = false,
                            error = "Passkey authentication failed",
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        passkeyLoading = false,
                        error = when {
                            e.message?.contains("cancelled", ignoreCase = true) == true ||
                            e.message?.contains("canceled", ignoreCase = true) == true ->
                                "Authentication was cancelled"
                            else -> e.message ?: "Passkey authentication failed"
                        },
                    )
                }
            }
        }
    }

    private fun generateBase64Challenge(): String {
        val bytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(bytes)
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

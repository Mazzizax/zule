package com.mazzizax.zule.ui.screen.login

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.OrphanedPasskeyException
import com.mazzizax.zule.data.repository.PasskeyRepository
import com.mazzizax.zule.util.PrivateLog
import com.mazzizax.zule.util.RecoveryHint
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Login view state.
 *
 * `error`, `errorHint`, and `errorSupportRef` replace the previous bare
 * `error: String?`. Hints drive the action row shown beneath the error
 * (re-enrol, open device security settings, retry with Google Password
 * Manager, contact support). `supportRef` carries an opaque reference
 * the user can quote when reaching out.
 */
data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val passkeyLoading: Boolean = false,
    val error: String? = null,
    val errorHint: RecoveryHint? = null,
    val errorSupportRef: String? = null,
)

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    private val passkeyRepository: PasskeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    fun onEmailChange(email: String) {
        _uiState.update { it.copy(email = email, error = null, errorHint = null, errorSupportRef = null) }
    }

    fun onPasswordChange(password: String) {
        _uiState.update { it.copy(password = password, error = null, errorHint = null, errorSupportRef = null) }
    }

    fun signIn(onSuccess: () -> Unit) {
        val state = _uiState.value
        if (state.email.isBlank() || state.password.isBlank()) {
            _uiState.update { it.copy(error = "Please enter email and password") }
            return
        }

        _uiState.update { it.copy(isLoading = true, error = null, errorHint = null, errorSupportRef = null) }

        viewModelScope.launch {
            try {
                authRepository.signIn(state.email.trim(), state.password)
                onSuccess()
            } catch (t: Throwable) {
                _uiState.update {
                    val e = asFriendlyEvent(t)
                    it.copy(
                        isLoading = false,
                        error = e.message,
                        errorHint = e.hint,
                        errorSupportRef = e.supportRef,
                    )
                }
            }
        }
    }

    /**
     * Server-driven passkey sign-in. Replaces the previous dead branch that
     * generated the challenge client-side and surfaced a "no callback URL"
     * error without minting a session.
     *
     * The new path calls passkey-auth-begin for a server-issued challenge,
     * passes it through Credential Manager, then calls passkey-auth-finish
     * which verifies the assertion and returns a real Supabase session that
     * we importSession into the current process.
     */
    fun signInWithPasskey(activity: Activity, onSuccess: () -> Unit) {
        _uiState.update { it.copy(passkeyLoading = true, error = null, errorHint = null, errorSupportRef = null) }

        viewModelScope.launch {
            try {
                passkeyRepository.signInWithPasskeyStrict(activity)
                onSuccess()
            } catch (t: Throwable) {
                PrivateLog.error("LoginViewModel", "signInWithPasskey failed", t)
                _uiState.update {
                    val e = asFriendlyEvent(t)
                    it.copy(
                        passkeyLoading = false,
                        error = e.message,
                        errorHint = e.hint,
                        errorSupportRef = e.supportRef,
                    )
                }
            }
        }
    }

    // -------- Error mapping --------

    private data class FriendlyEvent(
        val message: String,
        val hint: RecoveryHint? = null,
        val supportRef: String? = null,
    )

    private fun asFriendlyEvent(t: Throwable): FriendlyEvent {
        val msg = t.message ?: ""

        if (t is OrphanedPasskeyException) {
            return FriendlyEvent(
                "Your passkey was created, but we couldn't save it to our server. Try again — we'll overwrite the orphan.",
                hint = RecoveryHint.FORCE_REENROLL,
            )
        }

        val gms = parseGmsErrorCode(t)
        if (gms != null) {
            return when (gms) {
                50162 -> FriendlyEvent("We can't read your passkey on this device. Re-enrol to continue.", RecoveryHint.FORCE_REENROLL)
                50157 -> FriendlyEvent("This account already has a passkey enrolled here.", RecoveryHint.ALREADY_ENROLLED)
                50166 -> FriendlyEvent("Set up a screen lock (PIN, pattern, fingerprint) before enrolling a passkey.", RecoveryHint.NEEDS_SCREEN_LOCK)
                50178 -> FriendlyEvent("Credential Manager is in a weird state. Open settings and try Google Password Manager.", RecoveryHint.RETRY_WITH_GOOGLE_PM)
                50152, 50175 -> FriendlyEvent("Temporarily unavailable. Try again shortly.", RecoveryHint.CONTACT_SUPPORT, newSupportRef(gms))
                else -> FriendlyEvent("Something went wrong. Try again; if it persists, contact support.", RecoveryHint.CONTACT_SUPPORT, newSupportRef(gms))
            }
        }

        return when {
            msg.contains("email_already_registered", true) ->
                FriendlyEvent("An account with that email already exists. Try signing in instead.")
            msg.contains("Invalid login credentials", true) || msg.contains("invalid_credentials", true) ->
                FriendlyEvent("Wrong email or password.")
            msg.contains("Email not confirmed", true) ->
                FriendlyEvent("Check your email for the confirmation link we sent.")
            msg.contains("email_and_password_required", true) ->
                FriendlyEvent("Enter an email and password.")
            msg.contains("password_too_short", true) ->
                FriendlyEvent("Password must be at least 12 characters.")
            msg.contains("UnknownHostException", true) || msg.contains("Unable to resolve host", true) ->
                FriendlyEvent("No internet connection.")
            msg.contains("NoCredentialException", true) ->
                FriendlyEvent("No passkey on this device. Sign in with your password instead.")
            msg.contains("unknown_credential", true) ->
                FriendlyEvent("This passkey isn't recognised for any account. Sign in with your password.")
            msg.contains("rate_limited", true) ->
                FriendlyEvent("Too many attempts. Wait a few minutes and try again.")
            msg.contains("counter_rollback", true) ->
                FriendlyEvent("Your passkey failed a security check. For safety we need you to re-enrol it.", RecoveryHint.FORCE_REENROLL)
            msg.contains("challenge_expired", true) ->
                FriendlyEvent("That took too long. Tap the fingerprint button again.")
            msg.contains("cancel", true) ->
                FriendlyEvent("Cancelled.")
            else -> FriendlyEvent("Something went wrong. Try again.", RecoveryHint.CONTACT_SUPPORT, newSupportRef(null))
        }
    }

    private fun parseGmsErrorCode(t: Throwable): Int? {
        val m = Regex("501\\d{2}").find(t.message ?: "") ?: return null
        return m.value.toIntOrNull()
    }

    private fun newSupportRef(gmsCode: Int?): String {
        val ts = (System.currentTimeMillis() / 1000).toString(16).uppercase()
        val rand = (0..3).map { "0123456789ABCDEF".random() }.joinToString("")
        val gms = if (gmsCode != null) "-$gmsCode" else ""
        val ref = "Z-${ts.takeLast(6)}-$rand$gms"
        PrivateLog.safe("LoginViewModel", "support_ref=$ref")
        return ref
    }
}

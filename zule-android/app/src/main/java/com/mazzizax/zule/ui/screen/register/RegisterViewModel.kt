package com.mazzizax.zule.ui.screen.register

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.util.PwnedPasswordException
import com.mazzizax.zule.util.PwnedPasswords
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class RegisterUiState(
    val email: String = "",
    val password: String = "",
    val confirmPassword: String = "",
    val isLoading: Boolean = false,
    val error: String? = null,
    val success: Boolean = false,
)

@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegisterUiState())
    val uiState: StateFlow<RegisterUiState> = _uiState.asStateFlow()

    fun onEmailChange(email: String) {
        _uiState.update { it.copy(email = email, error = null) }
    }

    fun onPasswordChange(password: String) {
        _uiState.update { it.copy(password = password, error = null) }
    }

    fun onConfirmPasswordChange(confirmPassword: String) {
        _uiState.update { it.copy(confirmPassword = confirmPassword, error = null) }
    }

    fun signUp(onSuccess: () -> Unit) {
        val state = _uiState.value

        if (state.email.isBlank() || state.password.isBlank() || state.confirmPassword.isBlank()) {
            _uiState.update { it.copy(error = "Please fill in all fields") }
            return
        }

        if (state.password != state.confirmPassword) {
            _uiState.update { it.copy(error = "Passwords do not match") }
            return
        }

        if (state.password.length < 12) {
            _uiState.update { it.copy(error = "Password must be at least 12 characters") }
            return
        }

        _uiState.update { it.copy(isLoading = true, error = null) }

        viewModelScope.launch {
            try {
                // HIBP k-anonymity breach check — only first 5 hex chars of
                // SHA-1(password) leave the device. Fail-open on network error.
                val hibp = PwnedPasswords.check(state.password)
                if (hibp is PwnedPasswords.Result.Pwned) {
                    throw PwnedPasswordException(hibp.breachCount)
                }

                authRepository.signUp(state.email.trim().lowercase(), state.password)
                _uiState.update { it.copy(isLoading = false, success = true) }
                onSuccess()
            } catch (e: Throwable) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = when (e) {
                            is PwnedPasswordException ->
                                "Pick a different password — this one appears in ${e.breachCount} known breaches."
                            else -> friendlyError(e)
                        },
                    )
                }
            }
        }
    }

    private fun friendlyError(t: Throwable): String {
        val msg = t.message ?: ""
        return when {
            msg.contains("email_already_registered", true) ->
                "An account with that email already exists. Try signing in instead."
            msg.contains("password_too_short", true) ->
                "Password must be at least 12 characters."
            msg.contains("rate_limited", true) ->
                "Too many attempts. Wait a few minutes and try again."
            msg.contains("UnknownHostException", true) || msg.contains("Unable to resolve host", true) ->
                "No internet connection."
            else -> msg.ifBlank { "Could not create account" }
        }
    }
}

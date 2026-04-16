package com.mazzizax.zule.ui.screen.verifyemail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class VerifyEmailUiState(
    val userEmail: String? = null,
    val isSending: Boolean = false,
    val sent: Boolean = false,
    val error: String? = null,
    val cooldown: Int = 0,
)

@HiltViewModel
class VerifyEmailViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(VerifyEmailUiState())
    val uiState: StateFlow<VerifyEmailUiState> = _uiState.asStateFlow()

    init {
        _uiState.update { it.copy(userEmail = authRepository.currentUser()?.email) }
    }

    fun resendVerification() {
        _uiState.update { it.copy(isSending = true, error = null, sent = false) }

        viewModelScope.launch {
            try {
                authRepository.resendVerification()
                _uiState.update { it.copy(isSending = false, sent = true, cooldown = 60) }
                startCooldownTimer()
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isSending = false,
                        error = e.message ?: "Failed to send verification email",
                    )
                }
            }
        }
    }

    private fun startCooldownTimer() {
        viewModelScope.launch {
            while (_uiState.value.cooldown > 0) {
                delay(1000L)
                _uiState.update { it.copy(cooldown = it.cooldown - 1) }
            }
        }
    }

    fun signOutAndNavigateBack(onComplete: () -> Unit) {
        viewModelScope.launch {
            try {
                authRepository.signOut()
            } catch (_: Exception) {
                // Sign out best-effort
            }
            onComplete()
        }
    }
}

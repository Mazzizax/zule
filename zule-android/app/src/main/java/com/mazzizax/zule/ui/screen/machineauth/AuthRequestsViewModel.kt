package com.mazzizax.zule.ui.screen.machineauth

import android.app.Activity
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.MachineAuthRepository
import com.mazzizax.zule.data.repository.PasskeyRepository
import com.mazzizax.zule.domain.model.Passkey
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class AuthRequestsUiState(
    val sessions: List<MachineAuthRepository.PendingSession> = emptyList(),
    val passkeys: List<Passkey> = emptyList(),
    val isLoading: Boolean = true,
    val isApproving: String? = null, // session_id being approved
    val isDenying: String? = null,
    val message: String? = null,
)

@HiltViewModel
class AuthRequestsViewModel @Inject constructor(
    private val machineAuthRepository: MachineAuthRepository,
    private val passkeyRepository: PasskeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(AuthRequestsUiState())
    val uiState: StateFlow<AuthRequestsUiState> = _uiState.asStateFlow()

    init {
        loadData()
        startPolling()
    }

    private fun loadData() {
        viewModelScope.launch {
            // Load passkeys so we know which credential_id to use for approval
            passkeyRepository.listPasskeys().onSuccess { passkeys ->
                _uiState.update { it.copy(passkeys = passkeys) }
            }
            loadPendingSessions()
        }
    }

    private fun startPolling() {
        viewModelScope.launch {
            while (true) {
                delay(3000)
                loadPendingSessions()
            }
        }
    }

    private suspend fun loadPendingSessions() {
        machineAuthRepository.getPendingSessions().onSuccess { sessions ->
            _uiState.update { it.copy(isLoading = false, sessions = sessions) }
        }.onFailure {
            _uiState.update { it.copy(isLoading = false) }
        }
    }

    /**
     * Approve a session with passkey biometric.
     *
     * Flow (matches machine-auth-approve edge function):
     * 1. Need a credential_id — use the first active passkey
     * 2. GET ?action=challenge&session_id=X&credential_id=Y → options JSON + challenge_key
     * 3. Credential Manager getCredential() with options → AuthenticationResponseJSON
     * 4. POST { session_id, challenge_key, response } → approved
     */
    fun approveSession(sessionId: String, activity: Activity) {
        val state = _uiState.value
        val passkey = state.passkeys.firstOrNull()
        if (passkey == null) {
            _uiState.update { it.copy(message = "No passkey registered. Register one in Security settings.") }
            return
        }

        _uiState.update { it.copy(isApproving = sessionId, message = null) }

        viewModelScope.launch {
            try {
                // Step 1: Get challenge from server
                val (optionsJson, challengeKey) = machineAuthRepository
                    .getApproveChallenge(sessionId, passkey.credentialId)
                    .getOrThrow()

                // Step 2: Trigger Credential Manager biometric
                val credentialManager = CredentialManager.create(activity)
                val option = GetPublicKeyCredentialOption(requestJson = optionsJson)
                val request = GetCredentialRequest(listOf(option))
                val credentialResponse = credentialManager.getCredential(activity, request)
                val pkCredential = credentialResponse.credential as PublicKeyCredential
                val authResponseJson = pkCredential.authenticationResponseJson

                // Step 3: Send assertion to server for approval
                machineAuthRepository.approveSession(
                    sessionId = sessionId,
                    challengeKey = challengeKey,
                    authResponseJson = authResponseJson,
                ).getOrThrow()

                _uiState.update { it.copy(isApproving = null, message = "Session approved") }
                loadPendingSessions()
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isApproving = null,
                        message = when {
                            e.message?.contains("cancel", ignoreCase = true) == true -> "Approval cancelled"
                            else -> "Approval failed: ${e.message}"
                        },
                    )
                }
            }
        }
    }

    fun denySession(sessionId: String) {
        _uiState.update { it.copy(isDenying = sessionId, message = null) }

        viewModelScope.launch {
            machineAuthRepository.denySession(sessionId)
                .onSuccess {
                    _uiState.update { it.copy(isDenying = null, message = "Session denied") }
                    loadPendingSessions()
                }
                .onFailure {
                    _uiState.update { it.copy(isDenying = null, message = "Failed to deny session") }
                }
        }
    }
}

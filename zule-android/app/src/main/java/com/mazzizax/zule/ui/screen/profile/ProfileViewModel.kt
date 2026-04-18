package com.mazzizax.zule.ui.screen.profile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.ProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ProfileUiState(
    val isLoading: Boolean = true,
    val isSaving: Boolean = false,
    val email: String = "",
    val displayName: String = "",
    val timezone: String = "UTC",
    val error: String? = null,
    val success: String? = null,
)

@HiltViewModel
class ProfileViewModel @Inject constructor(
    private val profileRepository: ProfileRepository,
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProfileUiState())
    val uiState: StateFlow<ProfileUiState> = _uiState.asStateFlow()

    init {
        fetchProfile()
    }

    private fun fetchProfile() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            val user = authRepository.currentUser()
            profileRepository.getProfile()
                .onSuccess { profile ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            email = user?.email ?: "",
                            displayName = profile.displayName ?: "",
                            timezone = profile.timezone ?: "UTC",
                            error = null,
                        )
                    }
                }
                .onFailure {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            email = user?.email ?: "",
                            error = "Failed to load profile",
                        )
                    }
                }
        }
    }

    fun onDisplayNameChange(name: String) {
        if (name.length <= 50) {
            _uiState.update { it.copy(displayName = name, error = null, success = null) }
        }
    }

    fun onTimezoneChange(tz: String) {
        _uiState.update { it.copy(timezone = tz, error = null, success = null) }
    }

    fun saveProfile() {
        viewModelScope.launch {
            _uiState.update { it.copy(isSaving = true, error = null, success = null) }
            val state = _uiState.value
            profileRepository.updateProfile(
                displayName = state.displayName.ifBlank { null },
                timezone = state.timezone,
            )
                .onSuccess {
                    _uiState.update {
                        it.copy(
                            isSaving = false,
                            success = "Profile updated successfully",
                        )
                    }
                }
                .onFailure {
                    _uiState.update {
                        it.copy(
                            isSaving = false,
                            error = "Failed to update profile",
                        )
                    }
                }
        }
    }
}

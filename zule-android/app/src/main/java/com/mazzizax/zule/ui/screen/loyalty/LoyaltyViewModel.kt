package com.mazzizax.zule.ui.screen.loyalty

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.LoyaltyRepository
import com.mazzizax.zule.domain.model.LoyaltyCard
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Translation of Loyalty.tsx state + effects.
 *
 * Web state:
 *   cards: LoyaltyCard[]
 *   loading: boolean
 *   programName: string
 *   memberNumber: string
 *   adding: boolean
 *   scanning: boolean (barcode scanner state — placeholder on Android)
 *   removeLoadingId: string | null
 */

data class LoyaltyUiState(
    val cards: List<LoyaltyCard> = emptyList(),
    val loading: Boolean = true,
    val programName: String = "",
    val memberNumber: String = "",
    val adding: Boolean = false,
    val removeLoadingId: String? = null,
    val error: String? = null,
)

@HiltViewModel
class LoyaltyViewModel @Inject constructor(
    private val loyaltyRepository: LoyaltyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoyaltyUiState())
    val uiState: StateFlow<LoyaltyUiState> = _uiState.asStateFlow()

    init {
        fetchCards()
    }

    fun onProgramNameChange(value: String) {
        _uiState.update { it.copy(programName = value) }
    }

    fun onMemberNumberChange(value: String) {
        _uiState.update { it.copy(memberNumber = value) }
    }

    fun fetchCards() {
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true) }
            loyaltyRepository.listCards()
                .onSuccess { cards ->
                    _uiState.update { it.copy(cards = cards, loading = false) }
                }
                .onFailure {
                    _uiState.update { it.copy(loading = false) }
                }
        }
    }

    fun addCard() {
        val state = _uiState.value
        if (state.programName.isBlank() || state.memberNumber.isBlank()) return

        _uiState.update { it.copy(adding = true) }

        viewModelScope.launch {
            loyaltyRepository.addCard(
                programName = state.programName,
                memberNumber = state.memberNumber,
            ).onSuccess {
                _uiState.update { it.copy(programName = "", memberNumber = "", adding = false) }
                fetchCards()
            }.onFailure {
                _uiState.update { it.copy(adding = false) }
            }
        }
    }

    fun removeCard(cardId: String) {
        _uiState.update { it.copy(removeLoadingId = cardId) }

        viewModelScope.launch {
            loyaltyRepository.deleteCard(cardId)
            _uiState.update { it.copy(removeLoadingId = null) }
            fetchCards()
        }
    }
}

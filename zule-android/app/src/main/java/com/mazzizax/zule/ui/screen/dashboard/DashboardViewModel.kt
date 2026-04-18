package com.mazzizax.zule.ui.screen.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.PlaidRepository
import com.mazzizax.zule.data.repository.ProfileRepository
import com.mazzizax.zule.domain.model.PlaidAccount
import com.mazzizax.zule.domain.model.Subscription
import com.mazzizax.zule.domain.model.UserProfile
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Translation of Dashboard.tsx state management.
 *
 * Web app state and handlers:
 *   profile, loading, error, plaidLoading, removeLoadingId
 *   pullLoadingId, pullResult, analyzeLoading, analyzeResult
 *   gameCards, shredLoading, shredResult, lastAttestation
 *
 *   fetchProfile() → GET user-profile
 *   openPlaidLink() → POST plaid-create-link-token → Plaid widget → exchange → refresh
 *   pullTransactions(accountId) → POST plaid-pull-transactions
 *   analyzeAndSend() → POST mint-transaction-cards
 *   shredAndSend() → POST shred-minted-transactions
 *   removeCard(accountId) → POST remove-card → refresh
 */
data class DashboardUiState(
    val isLoading: Boolean = true,
    val profile: UserProfile? = null,
    val email: String? = null,
    val memberSince: String? = null,
    val lastActive: String? = null,
    val plaidAccounts: List<PlaidAccount> = emptyList(),
    val subscriptions: List<Subscription> = emptyList(),
    val plaidLoading: Boolean = false,
    val removeLoadingId: String? = null,
    val pullLoadingId: String? = null,
    val pullResult: String? = null,
    val analyzeLoading: Boolean = false,
    val analyzeResult: String? = null,
    val shredLoading: Boolean = false,
    val shredResult: String? = null,
    val lastAttestation: String? = null,
    val error: String? = null,
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val profileRepository: ProfileRepository,
    private val plaidRepository: PlaidRepository,
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        fetchProfile()
    }

    fun fetchProfile() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            profileRepository.getProfile()
                .onSuccess { profile ->
                    val user = authRepository.currentUser()
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            profile = profile,
                            email = user?.email,
                            memberSince = profile.createdAt ?: user?.createdAt?.toString(),
                            lastActive = profile.lastSeenAt,
                            plaidAccounts = profile.plaidAccounts ?: emptyList(),
                            subscriptions = profile.subscriptions ?: emptyList(),
                            error = null,
                        )
                    }
                }
                .onFailure {
                    _uiState.update { it.copy(isLoading = false, error = "Failed to load profile") }
                }
        }
    }

    /**
     * Translation of openPlaidLink() step 1: get link_token from backend.
     * Step 2 (opening Plaid Link SDK) happens at the Screen level via PlaidLinkHelper.
     * Step 3 (exchange token) is exchangePublicToken() below.
     */
    fun createLinkToken(onToken: (String) -> Unit) {
        viewModelScope.launch {
            _uiState.update { it.copy(plaidLoading = true) }
            plaidRepository.createLinkToken()
                .onSuccess { token -> onToken(token) }
                .onFailure {
                    _uiState.update { it.copy(plaidLoading = false, error = "Failed to create link token") }
                }
        }
    }

    fun exchangePublicToken(publicToken: String) {
        viewModelScope.launch {
            plaidRepository.exchangePublicToken(publicToken)
                .onSuccess { fetchProfile() }
                .onFailure {
                    _uiState.update { it.copy(error = "Failed to connect account. Please try again.") }
                }
            _uiState.update { it.copy(plaidLoading = false) }
        }
    }

    fun onPlaidExit() {
        _uiState.update { it.copy(plaidLoading = false) }
    }

    /**
     * Translation of pullTransactions(accountId) from Dashboard.tsx.
     */
    fun pullTransactions(accountId: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(pullLoadingId = accountId, pullResult = null) }
            plaidRepository.pullTransactions(accountId)
                .onSuccess { responseBody ->
                    _uiState.update { it.copy(pullLoadingId = null, pullResult = "Transactions synced") }
                }
                .onFailure {
                    _uiState.update { it.copy(pullLoadingId = null, error = "Failed to pull transactions") }
                }
        }
    }

    /**
     * Phase 1 — mint card_attestation from unminted Plaid transactions.
     * Extracts the attestation JWT from the response and stores it in
     * `lastAttestation` so phase 2 (sendToVinzrik) can fire the deep link.
     */
    fun mintCards() {
        viewModelScope.launch {
            _uiState.update { it.copy(analyzeLoading = true, analyzeResult = null, lastAttestation = null) }
            plaidRepository.mintTransactionCards()
                .onSuccess { responseBody ->
                    val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                    val root = runCatching {
                        json.parseToJsonElement(responseBody) as kotlinx.serialization.json.JsonObject
                    }.getOrNull()
                    val attestation = root
                        ?.get("card_attestation")
                        ?.let { if (it is kotlinx.serialization.json.JsonPrimitive) it.content else null }
                    val count = root
                        ?.get("card_count")
                        ?.let { if (it is kotlinx.serialization.json.JsonPrimitive) it.content.toIntOrNull() else null }
                        ?: 0
                    _uiState.update {
                        it.copy(
                            analyzeLoading = false,
                            analyzeResult = if (count == 0) "No new transactions to mint"
                            else "Minted $count game event cards",
                            lastAttestation = attestation,
                            shredResult = null,
                        )
                    }
                }
                .onFailure {
                    _uiState.update { it.copy(analyzeLoading = false, error = "Failed to mint cards") }
                }
        }
    }

    /** Alias for backward-compat during the rename transition. */
    fun analyzeAndSend() = mintCards()

    /**
     * Phase 2 — hand the card attestation off to Vinzrik via deep link.
     * Fire-and-forget: Vinzrik never calls back. Caller (screen) provides a
     * launcher that starts an Intent with the URI this function produces.
     */
    fun vinzrikPushUri(): android.net.Uri? {
        val att = _uiState.value.lastAttestation ?: return null
        return android.net.Uri.parse("vinzrik://receive-cards").buildUpon()
            .appendQueryParameter("attestation", att)
            .build()
    }

    fun noteSentToVinzrik() {
        _uiState.update { it.copy(shredResult = "Sent to Vinzrik. Confirm on Vinzrik, then shred.") }
    }

    /**
     * Phase 3 — shred raw transactions on zule's side. Cards should already
     * have been handed off via sendToVinzrik before this runs.
     */
    fun shredRaw() {
        viewModelScope.launch {
            _uiState.update { it.copy(shredLoading = true, shredResult = null) }
            plaidRepository.shredMintedTransactions()
                .onSuccess {
                    _uiState.update {
                        it.copy(
                            shredLoading = false,
                            shredResult = "Transactions shredded",
                            analyzeResult = null,
                            lastAttestation = null,
                        )
                    }
                }
                .onFailure {
                    _uiState.update { it.copy(shredLoading = false, error = "Failed to shred transactions") }
                }
        }
    }

    /** Alias for backward-compat during the rename transition. */
    fun shredAndSend() = shredRaw()

    fun removeCard(accountId: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(removeLoadingId = accountId) }
            plaidRepository.removeCard(accountId)
                .onSuccess { fetchProfile() }
                .onFailure {
                    _uiState.update { it.copy(error = "Failed to remove card") }
                }
            _uiState.update { it.copy(removeLoadingId = null) }
        }
    }

    fun signOut(onComplete: () -> Unit) {
        viewModelScope.launch {
            try {
                authRepository.signOut()
            } catch (_: Exception) { }
            onComplete()
        }
    }
}

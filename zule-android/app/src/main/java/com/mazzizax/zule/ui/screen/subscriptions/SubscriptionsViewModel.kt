package com.mazzizax.zule.ui.screen.subscriptions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mazzizax.zule.data.repository.ProfileRepository
import com.mazzizax.zule.data.repository.SubscriptionRepository
import com.mazzizax.zule.domain.model.Subscription
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Translation of Subscriptions.tsx state + effects.
 *
 * Web state:
 *   selectedService: string | null (from searchParams or click)
 *   subscriptions: Subscription[] (from user-profile GET)
 *   purchases: { product_id: string }[] (from user-profile GET)
 *   checkoutLoading: string | null (key = "serviceId-stripePriceId")
 *   cancelConfirm: boolean
 *   cancelLoading: boolean
 *   upgradeTarget: { serviceId, tierId, tierName, priceId, price } | null
 *   upgradeLoading: boolean
 */

data class Purchase(val productId: String)

data class UpgradeTarget(
    val serviceId: String,
    val tierId: String,
    val tierName: String,
    val priceId: String,
    val price: String,
)

data class SubscriptionsUiState(
    val selectedServiceId: String? = null,
    val subscriptions: List<Subscription> = emptyList(),
    val purchases: List<Purchase> = emptyList(),
    val checkoutLoadingKey: String? = null,
    val cancelConfirm: Boolean = false,
    val cancelLoading: Boolean = false,
    val upgradeTarget: UpgradeTarget? = null,
    val upgradeLoading: Boolean = false,
    val error: String? = null,
)

@HiltViewModel
class SubscriptionsViewModel @Inject constructor(
    private val profileRepository: ProfileRepository,
    private val subscriptionRepository: SubscriptionRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SubscriptionsUiState())
    val uiState: StateFlow<SubscriptionsUiState> = _uiState.asStateFlow()

    init {
        fetchSubscriptions()
    }

    fun selectService(serviceId: String?) {
        _uiState.update { it.copy(selectedServiceId = serviceId, cancelConfirm = false, upgradeTarget = null) }
    }

    fun fetchSubscriptions() {
        viewModelScope.launch {
            profileRepository.getProfile().onSuccess { profile ->
                _uiState.update {
                    it.copy(
                        subscriptions = profile.subscriptions ?: emptyList(),
                        purchases = (profile.purchases ?: emptyList()).map { p -> Purchase(productId = p.productId) },
                    )
                }
            }
        }
    }

    /**
     * Creates a Stripe checkout session and returns the checkout URL.
     * The screen composable opens this URL in a Custom Chrome Tab.
     *
     * Web app: handleSubscribe → POST create-checkout → window.open(url)
     * Android: POST create-checkout → return URL → CustomTabsIntent
     */
    fun subscribe(
        serviceId: String,
        stripePriceId: String,
        productId: String? = null,
        mode: String = "subscription",
        onCheckoutUrl: (String) -> Unit,
    ) {
        val loadingKey = "$serviceId-$stripePriceId"
        _uiState.update { it.copy(checkoutLoadingKey = loadingKey) }

        viewModelScope.launch {
            subscriptionRepository.createCheckout(
                priceId = stripePriceId,
                serviceId = serviceId,
                productId = productId,
                mode = mode,
            ).onSuccess { url ->
                _uiState.update { it.copy(checkoutLoadingKey = null) }
                onCheckoutUrl(url)
            }.onFailure { e ->
                _uiState.update { it.copy(checkoutLoadingKey = null, error = e.message) }
            }
        }
    }

    /**
     * Prompts the upgrade confirmation inline.
     * Web app: setUpgradeTarget({...})
     */
    fun showUpgradeConfirmation(target: UpgradeTarget) {
        _uiState.update { it.copy(upgradeTarget = target) }
    }

    fun dismissUpgrade() {
        _uiState.update { it.copy(upgradeTarget = null) }
    }

    /**
     * Executes the upgrade (switch tier).
     * Web app: handleUpgrade → POST upgrade-subscription → wait 2s → refresh
     */
    fun confirmUpgrade() {
        val target = _uiState.value.upgradeTarget ?: return
        _uiState.update { it.copy(upgradeLoading = true) }

        viewModelScope.launch {
            subscriptionRepository.upgradeSubscription(
                serviceId = target.serviceId,
                newPriceId = target.priceId,
            ).onSuccess {
                _uiState.update { it.copy(upgradeTarget = null) }
                // Wait for webhook to update the DB, then refresh
                delay(2000)
                fetchSubscriptions()
            }.onFailure { e ->
                _uiState.update { it.copy(error = e.message) }
            }
            _uiState.update { it.copy(upgradeLoading = false) }
        }
    }

    fun showCancelConfirm() {
        _uiState.update { it.copy(cancelConfirm = true) }
    }

    fun dismissCancelConfirm() {
        _uiState.update { it.copy(cancelConfirm = false) }
    }

    /**
     * Cancels the active subscription for the given service.
     * Web app: handleCancel → POST cancel-subscription → refresh
     */
    fun confirmCancel(serviceId: String) {
        _uiState.update { it.copy(cancelLoading = true) }

        viewModelScope.launch {
            subscriptionRepository.cancelSubscription(serviceId = serviceId)
                .onSuccess {
                    _uiState.update { it.copy(cancelConfirm = false) }
                    fetchSubscriptions()
                }
                .onFailure { e ->
                    _uiState.update { it.copy(error = e.message) }
                }
            _uiState.update { it.copy(cancelLoading = false) }
        }
    }

    fun getActiveSubscription(serviceId: String): Subscription? {
        return _uiState.value.subscriptions.find { it.serviceId == serviceId && it.status == "active" }
    }

    fun getPurchaseCount(productId: String?): Int {
        if (productId == null) return 0
        return _uiState.value.purchases.count { it.productId == productId }
    }
}

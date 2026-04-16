package com.mazzizax.zule.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class UserProfile(
    @SerialName("display_name") val displayName: String? = null,
    val timezone: String? = null,
    val email: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("subscription_tier") val subscriptionTier: String? = null,
    @SerialName("subscription_status") val subscriptionStatus: String? = null,
    @SerialName("plaid_accounts") val plaidAccounts: List<PlaidAccount>? = null,
    val subscriptions: List<Subscription>? = null,
    val purchases: List<Purchase>? = null,
)

@Serializable
data class Purchase(
    @SerialName("product_id") val productId: String,
)

package com.mazzizax.zule.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Subscription(
    @SerialName("service_id") val serviceId: String,
    val tier: String,
    val status: String,
    @SerialName("stripe_subscription_id") val stripeSubscriptionId: String? = null,
    @SerialName("expires_at") val expiresAt: String? = null,
)

package com.mazzizax.zule.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Passkey(
    val id: String,
    @SerialName("credential_id") val credentialId: String,
    @SerialName("device_name") val deviceName: String,
    @SerialName("authenticator_type") val authenticatorType: String = "platform",
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_used_at") val lastUsedAt: String? = null,
    @SerialName("is_active") val isActive: Boolean = true,
)

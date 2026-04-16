package com.mazzizax.zule.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PlaidAccount(
    val id: String,
    @SerialName("institution_name") val institutionName: String,
    @SerialName("connected_at") val connectedAt: String,
    val status: String? = null,
)

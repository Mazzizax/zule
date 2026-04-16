package com.mazzizax.zule.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LoyaltyCard(
    val id: String,
    @SerialName("program_name") val programName: String,
    @SerialName("member_number") val memberNumber: String,
    @SerialName("barcode_format") val barcodeFormat: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
)

package com.mazzizax.zule.data.repository

import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.functions.functions
import io.ktor.client.call.body
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class SubscriptionRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun createCheckout(
        priceId: String,
        serviceId: String,
        productId: String? = null,
        mode: String = "subscription",
    ): Result<String> {
        return try {
            val response = supabase.functions.invoke("create-checkout") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("price_id", priceId)
                    put("service_id", serviceId)
                    productId?.let { put("product_id", it) }
                    put("mode", mode)
                    put("success_url", "zule://subscriptions?success=true&service=$serviceId")
                    put("cancel_url", "zule://subscriptions?service=$serviceId")
                }.toString())
            }
            val responseBody = response.body<String>()
            val data = json.parseToJsonElement(responseBody) as JsonObject
            val url = data["url"].toString().trim('"')
            Result.success(url)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun cancelSubscription(serviceId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("cancel-subscription") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("service_id", serviceId)
                }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun upgradeSubscription(serviceId: String, newPriceId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("upgrade-subscription") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("service_id", serviceId)
                    put("new_price_id", newPriceId)
                }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

package com.mazzizax.zule.data.repository

import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.functions.functions
import io.ktor.client.call.body
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Translation of Subscriptions.tsx checkout/upgrade/cancel API calls.
 *
 * Web app calls:
 *   POST /functions/v1/create-checkout → { url }
 *   POST /functions/v1/upgrade-subscription → success/failure
 *   POST /functions/v1/cancel-subscription → success/failure
 *
 * All three are POST-only edge functions. The Supabase Kotlin SDK
 * defaults to POST for functions.invoke(), so no explicit method override needed.
 */
class SubscriptionRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * POST /functions/v1/create-checkout
     *
     * Creates a Stripe checkout session and returns the checkout URL.
     *
     * Web app: handleSubscribe() in Subscriptions.tsx
     * Request body: { price_id, service_id, product_id?, mode, success_url, cancel_url }
     * Response: { url: string }
     *
     * On Android, success_url and cancel_url use deep links instead of web URLs.
     */
    suspend fun createCheckout(
        priceId: String,
        serviceId: String,
        productId: String? = null,
        mode: String = "subscription",
    ): Result<String> {
        return try {
            val response = supabase.functions.invoke("create-checkout") {
                body = buildJsonObject {
                    put("price_id", priceId)
                    put("service_id", serviceId)
                    productId?.let { put("product_id", it) }
                    put("mode", mode)
                    // Deep link URLs for Android — the activity handles the callback
                    put("success_url", "zule://subscriptions?success=true&service=$serviceId")
                    put("cancel_url", "zule://subscriptions?service=$serviceId")
                }
            }
            val responseBody = response.body<String>()
            val data = json.parseToJsonElement(responseBody) as JsonObject
            val url = data["url"].toString().trim('"')
            Result.success(url)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * POST /functions/v1/cancel-subscription
     *
     * Cancels the active subscription for a service.
     *
     * Web app: handleCancel() in Subscriptions.tsx
     * Request body: { service_id }
     */
    suspend fun cancelSubscription(serviceId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("cancel-subscription") {
                body = buildJsonObject {
                    put("service_id", serviceId)
                }
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * POST /functions/v1/upgrade-subscription
     *
     * Switches to a different tier within the same service.
     *
     * Web app: handleUpgrade() in Subscriptions.tsx
     * Request body: { service_id, new_price_id }
     */
    suspend fun upgradeSubscription(serviceId: String, newPriceId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("upgrade-subscription") {
                body = buildJsonObject {
                    put("service_id", serviceId)
                    put("new_price_id", newPriceId)
                }
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

package com.mazzizax.zule.data.repository

import com.mazzizax.zule.domain.model.UserProfile
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.functions.functions
import io.ktor.client.call.body
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Translation of Dashboard.tsx, Profile.tsx, and Subscriptions.tsx profile API calls.
 *
 * Web app calls:
 *   GET  /functions/v1/user-profile → full profile (subscriptions, plaid_accounts, etc.)
 *   PUT  /functions/v1/user-profile → update profile fields { display_name, timezone }
 *   POST /functions/v1/remove-card  → remove Plaid account { account_id }
 *
 * The GET response includes subscriptions, purchases, and plaid_accounts arrays
 * used by Dashboard, Profile, and Subscriptions screens.
 */
class ProfileRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * GET /functions/v1/user-profile
     *
     * Returns full profile including subscriptions, plaid accounts, and purchases.
     * Web: fetchProfile() in Dashboard.tsx, Profile.tsx; fetchSubscriptions() in Subscriptions.tsx
     */
    suspend fun getProfile(): Result<UserProfile> {
        return try {
            val response = supabase.functions.invoke("user-profile") {
                method = HttpMethod.Get
            }
            val responseBody = response.body<String>()
            Result.success(json.decodeFromString(responseBody))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * PUT /functions/v1/user-profile
     *
     * Updates profile fields.
     * Web: handleSave() in Profile.tsx → PUT { display_name, timezone }
     */
    suspend fun updateProfile(
        displayName: String? = null,
        timezone: String? = null,
    ): Result<Unit> {
        return try {
            supabase.functions.invoke("user-profile") {
                method = HttpMethod.Put
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("display_name", displayName)
                    timezone?.let { put("timezone", it) }
                }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * POST /functions/v1/remove-card
     *
     * Removes a connected Plaid account.
     * Web: removeCard(accountId) in Dashboard.tsx
     */
    suspend fun removeCard(accountId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("remove-card") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("account_id", accountId)
                }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

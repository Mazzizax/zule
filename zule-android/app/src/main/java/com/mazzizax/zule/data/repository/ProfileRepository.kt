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

class ProfileRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

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

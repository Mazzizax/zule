package com.mazzizax.zule.data.repository

import com.mazzizax.zule.domain.model.LoyaltyCard
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
 * Translation of Loyalty.tsx API calls.
 *
 * Edge function loyalty-cards dispatches on method:
 *   GET → list cards
 *   POST → add card
 *   DELETE → remove card
 */
class LoyaltyRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun listCards(): Result<List<LoyaltyCard>> {
        return try {
            val response = supabase.functions.invoke("loyalty-cards") {
                method = HttpMethod.Get
            }
            val responseBody = response.body<String>()
            Result.success(json.decodeFromString(responseBody))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun addCard(programName: String, memberNumber: String): Result<Unit> {
        return try {
            supabase.functions.invoke("loyalty-cards") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("program_name", programName)
                    put("member_number", memberNumber)
                }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun deleteCard(cardId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("loyalty-cards") {
                method = HttpMethod.Delete
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("id", cardId) }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

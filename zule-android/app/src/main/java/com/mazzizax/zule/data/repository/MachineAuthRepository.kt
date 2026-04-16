package com.mazzizax.zule.data.repository

import com.mazzizax.zule.BuildConfig
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Machine auth operations using raw HTTP — same pattern as web app fetch() calls.
 *
 * machine-auth-pending (GET): list pending sessions
 * machine-auth-approve (GET ?action=challenge&session_id=X&credential_id=Y): get passkey challenge
 * machine-auth-approve (POST { session_id, challenge_key, response }): approve with passkey
 * machine-auth-approve (POST { session_id, action: 'deny' }): deny
 */
class MachineAuthRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }
    private val client = HttpClient(OkHttp)
    private val baseUrl = "${BuildConfig.SUPABASE_URL}/functions/v1"

    private suspend fun authHeader(): String {
        val token = supabase.auth.currentAccessTokenOrNull()
            ?: throw IllegalStateException("Not authenticated")
        return "Bearer $token"
    }

    @Serializable
    data class PendingSession(
        @SerialName("session_id") val sessionId: String,
        @SerialName("machine_name") val machineName: String,
        @SerialName("machine_id") val machineId: String,
        @SerialName("session_code") val sessionCode: String,
        @SerialName("expires_at") val expiresAt: String,
        @SerialName("created_at") val createdAt: String,
    )

    @Serializable
    private data class PendingResponse(val sessions: List<PendingSession>)

    suspend fun getPendingSessions(): Result<List<PendingSession>> {
        return try {
            val response = client.get("$baseUrl/machine-auth-pending") {
                header("Authorization", authHeader())
            }
            val body = response.body<String>()
            val data = json.decodeFromString<PendingResponse>(body)
            Result.success(data.sessions)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getApproveChallenge(
        sessionId: String,
        credentialId: String,
    ): Result<Pair<String, String>> {
        return try {
            val sid = java.net.URLEncoder.encode(sessionId, "UTF-8")
            val cid = java.net.URLEncoder.encode(credentialId, "UTF-8")
            val response = client.get("$baseUrl/machine-auth-approve?action=challenge&session_id=$sid&credential_id=$cid") {
                header("Authorization", authHeader())
            }
            val body = response.body<String>()
            val data = json.parseToJsonElement(body) as JsonObject
            val optionsJson = data["options"].toString()
            val challengeKey = data["challenge_key"].toString().trim('"')
            Result.success(Pair(optionsJson, challengeKey))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun approveSession(
        sessionId: String,
        challengeKey: String,
        authResponseJson: String,
    ): Result<Unit> {
        return try {
            val requestBody = buildJsonObject {
                put("session_id", sessionId)
                put("challenge_key", challengeKey)
                put("response", json.parseToJsonElement(authResponseJson))
            }
            client.post("$baseUrl/machine-auth-approve") {
                header("Authorization", authHeader())
                contentType(ContentType.Application.Json)
                setBody(requestBody.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun denySession(sessionId: String): Result<Unit> {
        return try {
            val requestBody = buildJsonObject {
                put("session_id", sessionId)
                put("action", "deny")
            }
            client.post("$baseUrl/machine-auth-approve") {
                header("Authorization", authHeader())
                contentType(ContentType.Application.Json)
                setBody(requestBody.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

package com.mazzizax.zule.data.repository

import com.mazzizax.zule.BuildConfig
import com.mazzizax.zule.domain.model.Passkey
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.delete
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
 * Passkey operations using raw HTTP calls — same pattern as the web app's
 * fetch() calls in lib/webauthn.ts.
 *
 * The web app does NOT use the Supabase JS client for these calls.
 * It uses raw fetch with explicit method, URL, and Authorization header.
 * This translation does the same with Ktor HttpClient.
 */
class PasskeyRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }
    private val client = HttpClient(OkHttp)
    private val baseUrl = "${BuildConfig.SUPABASE_URL}/functions/v1"

    private suspend fun authHeader(): String {
        val token = supabase.auth.currentAccessTokenOrNull()
            ?: throw IllegalStateException("Not authenticated")
        return "Bearer $token"
    }

    @Serializable
    private data class PasskeyListResponse(val passkeys: List<Passkey>)

    @Serializable
    data class RegistrationOptionsResponse(
        val options: JsonObject,
        @SerialName("challenge_key") val challengeKey: String,
    )

    /**
     * GET /functions/v1/passkey-register
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-register`, { method: 'GET', headers: { Authorization } })
     */
    suspend fun listPasskeys(): Result<List<Passkey>> {
        return try {
            val response = client.get("$baseUrl/passkey-register") {
                header("Authorization", authHeader())
            }
            val body = response.body<String>()
            val data = json.decodeFromString<PasskeyListResponse>(body)
            Result.success(data.passkeys)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * GET /functions/v1/passkey-register?action=options
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-register?action=options`, { headers: { Authorization } })
     */
    suspend fun getRegistrationOptions(): Result<RegistrationOptionsResponse> {
        return try {
            val response = client.get("$baseUrl/passkey-register?action=options") {
                header("Authorization", authHeader())
            }
            val body = response.body<String>()
            Result.success(json.decodeFromString(body))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * POST /functions/v1/passkey-register
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-register`, { method: 'POST', headers: { Authorization, Content-Type }, body: JSON.stringify({...}) })
     */
    suspend fun registerPasskey(
        challengeKey: String,
        responseJson: String,
        deviceName: String,
    ): Result<Unit> {
        return try {
            val requestBody = buildJsonObject {
                put("challenge_key", challengeKey)
                put("response", json.parseToJsonElement(responseJson))
                put("device_name", deviceName)
            }
            client.post("$baseUrl/passkey-register") {
                header("Authorization", authHeader())
                contentType(ContentType.Application.Json)
                setBody(requestBody.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * DELETE /functions/v1/passkey-register
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-register`, { method: 'DELETE', headers: { Authorization, Content-Type }, body: JSON.stringify({ passkey_id }) })
     */
    suspend fun deletePasskey(passkeyId: String): Result<Unit> {
        return try {
            val requestBody = buildJsonObject { put("passkey_id", passkeyId) }
            client.delete("$baseUrl/passkey-register") {
                header("Authorization", authHeader())
                contentType(ContentType.Application.Json)
                setBody(requestBody.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * GET /functions/v1/passkey-auth?credential_id=X
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-auth?credential_id=${encodeURIComponent(credentialId)}`)
     */
    suspend fun getAuthChallenge(credentialId: String): Result<Pair<String, String>> {
        return try {
            val encoded = java.net.URLEncoder.encode(credentialId, "UTF-8")
            val response = client.get("$baseUrl/passkey-auth?credential_id=$encoded") {
                header("Authorization", authHeader())
            }
            val body = response.body<String>()
            val data = json.parseToJsonElement(body) as JsonObject
            val challenge = data["challenge"].toString().trim('"')
            val challengeKey = data["challenge_key"].toString().trim('"')
            Result.success(Pair(challenge, challengeKey))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * POST /functions/v1/passkey-auth
     * Web: fetch(`${ZULE_URL}/functions/v1/passkey-auth`, { method: 'POST', headers: { Content-Type }, body: JSON.stringify({...}) })
     */
    suspend fun verifyPasskeyAuth(
        challengeKey: String,
        credentialId: String,
        authenticatorData: String,
        clientDataJson: String,
        signature: String,
    ): Result<Unit> {
        return try {
            val requestBody = buildJsonObject {
                put("challenge_key", challengeKey)
                put("credential_id", credentialId)
                put("authenticator_data", authenticatorData)
                put("client_data_json", clientDataJson)
                put("signature", signature)
            }
            client.post("$baseUrl/passkey-auth") {
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

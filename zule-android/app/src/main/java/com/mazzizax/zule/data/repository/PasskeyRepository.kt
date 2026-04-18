package com.mazzizax.zule.data.repository

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import com.mazzizax.zule.BuildConfig
import com.mazzizax.zule.domain.model.Passkey
import com.mazzizax.zule.util.PrivateLog
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.user.UserSession
import io.github.jan.supabase.functions.functions
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
 * Thrown when Credential Manager created the passkey locally (it lives in
 * Google Password Manager) but the server registration step failed. The
 * correct recovery is to retry enrollment — WebAuthn replacement semantics
 * for the same RP+user pair overwrite the orphan.
 */
class OrphanedPasskeyException(
    val credentialId: String?,
    override val cause: Throwable,
) : RuntimeException("Passkey created on device but server registration failed", cause)

class PasskeyRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = false }
    private val client = HttpClient(OkHttp)
    private val baseUrl = "${BuildConfig.SUPABASE_URL}/functions/v1"

    @Serializable
    private data class BeginResp(val handle: String, val options: JsonObject)

    @Serializable
    private data class FinishResp(
        val verified: Boolean,
        val credentialId: String? = null,
    )

    @Serializable
    private data class SessionResp(
        val verified: Boolean,
        val access_token: String,
        val refresh_token: String,
        val expires_in: Long,
        val token_type: String,
    )

    /**
     * Failure of the finish step leaves the credential live in Google
     * Password Manager but unknown to the server — surfaced as
     * OrphanedPasskeyException so the caller can prompt a retry (which
     * overwrites the orphan under WebAuthn replacement semantics).
     */
    suspend fun enrollPasskeyStrict(activity: Activity) {
        val beginBody = client.post("$baseUrl/passkey-register-begin") {
            header("Authorization", authHeader())
            contentType(ContentType.Application.Json)
            setBody("{}")
        }.body<String>()
        val begin = json.decodeFromString<BeginResp>(beginBody)

        val manager = CredentialManager.create(activity)
        val optionsJson = begin.options.toString()
        val createRequest = CreatePublicKeyCredentialRequest(requestJson = optionsJson)
        val createResponse = manager.createCredential(activity, createRequest)
            as CreatePublicKeyCredentialResponse
        val registrationResponseJson = createResponse.registrationResponseJson

        var credentialId: String? = null
        try {
            val responseObj = json.parseToJsonElement(registrationResponseJson) as JsonObject
            credentialId = responseObj["id"]?.toString()?.trim('"')

            val finishBody = buildJsonObject {
                put("handle", begin.handle)
                put("response", responseObj)
            }
            val finishResp = client.post("$baseUrl/passkey-register-finish") {
                header("Authorization", authHeader())
                contentType(ContentType.Application.Json)
                setBody(finishBody.toString())
            }.body<String>()
            val result = json.decodeFromString<FinishResp>(finishResp)
            if (!result.verified) {
                throw RuntimeException("Server did not verify registration")
            }
        } catch (t: Throwable) {
            PrivateLog.safe("PasskeyRepository", "register-finish failed; orphaned passkey")
            PrivateLog.detail("PasskeyRepository", registrationResponseJson, t)
            throw OrphanedPasskeyException(credentialId, t)
        }
    }

    suspend fun signInWithPasskeyStrict(activity: Activity) {
        val beginBody = client.post("$baseUrl/passkey-auth-begin") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }.body<String>()
        val begin = json.decodeFromString<BeginResp>(beginBody)

        val manager = CredentialManager.create(activity)
        val optionsJson = begin.options.toString()
        val option = GetPublicKeyCredentialOption(requestJson = optionsJson)
        val request = GetCredentialRequest(listOf(option))
        val getResponse = manager.getCredential(activity, request)
        val pk = getResponse.credential as PublicKeyCredential
        val assertionJson = pk.authenticationResponseJson
        val assertionObj = json.parseToJsonElement(assertionJson) as JsonObject

        val finishBody = buildJsonObject {
            put("handle", begin.handle)
            put("response", assertionObj)
        }
        val finishResp = client.post("$baseUrl/passkey-auth-finish") {
            contentType(ContentType.Application.Json)
            setBody(finishBody.toString())
        }.body<String>()
        val session = json.decodeFromString<SessionResp>(finishResp)
        if (!session.verified) {
            throw RuntimeException("Server did not verify assertion")
        }

        supabase.auth.importSession(
            UserSession(
                accessToken = session.access_token,
                refreshToken = session.refresh_token,
                providerRefreshToken = null,
                providerToken = null,
                expiresIn = session.expires_in,
                tokenType = session.token_type,
                user = null,
            ),
        )
        supabase.auth.retrieveUserForCurrentSession(updateSession = true)
    }

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

}

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

/**
 * Translation of Dashboard.tsx Plaid operations.
 *
 * All Plaid edge functions expect POST:
 *   plaid-create-link-token → POST
 *   plaid-exchange-token → POST
 *   plaid-update-link-token → POST
 *   plaid-pull-transactions → POST
 *   mint-transaction-cards → POST
 *   shred-minted-transactions → POST
 *   remove-card → POST
 */
class PlaidRepository(private val supabase: SupabaseClient) {

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun createLinkToken(): Result<String> {
        return try {
            val response = supabase.functions.invoke("plaid-create-link-token")
            val responseBody = response.body<String>()
            val data = json.parseToJsonElement(responseBody) as JsonObject
            val linkToken = data["link_token"].toString().trim('"')
            Result.success(linkToken)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun exchangePublicToken(publicToken: String): Result<Unit> {
        return try {
            supabase.functions.invoke("plaid-exchange-token") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("public_token", publicToken) }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun pullTransactions(accountId: String): Result<String> {
        return try {
            val response = supabase.functions.invoke("plaid-pull-transactions") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("account_id", accountId) }.toString())
            }
            val responseBody = response.body<String>()
            Result.success(responseBody)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun mintTransactionCards(): Result<String> {
        return try {
            val response = supabase.functions.invoke("mint-transaction-cards")
            val responseBody = response.body<String>()
            Result.success(responseBody)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun shredMintedTransactions(): Result<String> {
        return try {
            val response = supabase.functions.invoke("shred-minted-transactions")
            val responseBody = response.body<String>()
            Result.success(responseBody)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun removeCard(accountId: String): Result<Unit> {
        return try {
            supabase.functions.invoke("remove-card") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("account_id", accountId) }.toString())
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

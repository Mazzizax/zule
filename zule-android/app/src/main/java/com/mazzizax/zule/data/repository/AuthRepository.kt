package com.mazzizax.zule.data.repository

import com.mazzizax.zule.data.SessionManager
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.providers.builtin.Email
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.functions.functions
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
private data class EmailBody(val email: String)

@Serializable
private data class SignUpBody(val email: String, val password: String)

private val functionsJson = Json { encodeDefaults = false }

class AuthRepository(
    private val supabase: SupabaseClient,
    private val sessionManager: SessionManager,
) {
    val sessionStatus: Flow<SessionStatus> = supabase.auth.sessionStatus

    val isAuthenticated: Flow<Boolean> = sessionStatus.map { it is SessionStatus.Authenticated }

    suspend fun signIn(email: String, password: String) {
        supabase.auth.signInWith(Email) {
            this.email = email
            this.password = password
        }
        sessionManager.startSessionTimers()
    }

    /**
     * Routes signup through the auth-signup Edge Function so the confirmation
     * email is branded and the link points directly at our App-Linked host.
     * The Supabase SDK's default signUpWith(Email) email path bounces through
     * SUPABASE_URL/auth/v1/verify which Android App Links do not intercept.
     */
    suspend fun signUp(email: String, password: String) {
        supabase.functions.invoke("auth-signup") {
            contentType(ContentType.Application.Json)
            setBody(functionsJson.encodeToString(SignUpBody.serializer(), SignUpBody(email, password)))
        }
    }

    suspend fun signOut() {
        sessionManager.stopSessionTimers()
        supabase.auth.signOut()
    }

    suspend fun signOutGlobal() {
        sessionManager.stopSessionTimers()
        supabase.auth.signOut(io.github.jan.supabase.auth.SignOutScope.GLOBAL)
    }

    /**
     * Re-sends a sign-in/confirmation link via auth-resend. The magic-link
     * type doubles as email confirmation for unverified accounts and as a
     * plain sign-in link for verified ones.
     */
    suspend fun resendVerification(email: String? = null) {
        val target = email?.trim()?.lowercase()
            ?: currentUser()?.email
            ?: throw IllegalStateException("No email available")
        supabase.functions.invoke("auth-resend") {
            contentType(ContentType.Application.Json)
            setBody(functionsJson.encodeToString(EmailBody.serializer(), EmailBody(target)))
        }
    }

    /**
     * Fires a password-reset email via auth-reset. Server always returns
     * ok:true to prevent email enumeration; this method succeeds even if
     * the address has no registered account.
     */
    suspend fun requestPasswordReset(email: String) {
        supabase.functions.invoke("auth-reset") {
            contentType(ContentType.Application.Json)
            setBody(functionsJson.encodeToString(EmailBody.serializer(), EmailBody(email.trim().lowercase())))
        }
    }

    suspend fun updatePassword(newPassword: String) {
        supabase.auth.updateUser { password = newPassword }
    }

    suspend fun deleteAccount(): Result<Unit> {
        return try {
            supabase.functions.invoke("delete-account")
            sessionManager.clearSession()
            supabase.auth.signOut()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun currentUser(): UserInfo? = supabase.auth.currentUserOrNull()

    fun isEmailVerified(): Boolean = currentUser()?.emailConfirmedAt != null

    suspend fun getAccessToken(): String? {
        return supabase.auth.currentAccessTokenOrNull()
    }
}

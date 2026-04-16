package com.mazzizax.zule.data.repository

import com.mazzizax.zule.data.SessionManager
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.providers.builtin.Email
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.functions.functions
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Translation of AuthContext.tsx auth operations.
 *
 * Web app functions translated:
 *   signIn(email, password) → signInWithPassword + kill signal broadcast + timer start
 *   signUp(email, password) → signUp
 *   signOut() → stopTimers + signOut
 *   resendVerification() → resend({type:'signup', email})
 *   emailVerified → !!user?.email_confirmed_at
 *
 * The kill signal (localStorage.setItem(KILL_SIGNAL_KEY, crypto.randomUUID()))
 * has no Android equivalent — single instance per device.
 *
 * Global signout matches: supabase.auth.signOut({ scope: 'global' })
 * Delete account matches: POST /functions/v1/delete-account then signOut
 */
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

    suspend fun signUp(email: String, password: String) {
        supabase.auth.signUpWith(Email) {
            this.email = email
            this.password = password
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

    suspend fun resendVerification() {
        val email = currentUser()?.email ?: throw IllegalStateException("No email available")
        supabase.auth.resendEmail(io.github.jan.supabase.auth.OtpType.Email.SIGNUP, email)
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

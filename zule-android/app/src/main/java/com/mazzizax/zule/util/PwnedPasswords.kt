package com.mazzizax.zule.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Have I Been Pwned — k-anonymity password-breach check.
 *
 * Sends only the first 5 hex chars of SHA-1(password) to
 * api.pwnedpasswords.com/range. The service returns the list of 35-char
 * suffixes with breach counts; we find our suffix locally. Plaintext
 * password, full hash, and any user identifier never leave the device.
 *
 * Fails open: if the network is unreachable or the service misbehaves we
 * return `NetworkUnavailable` and the caller proceeds. Denying signup
 * because HIBP is down would be worse than a weak password slipping past
 * one check.
 */
object PwnedPasswords {

    sealed interface Result {
        data object Clean : Result
        data class Pwned(val breachCount: Int) : Result
        data object NetworkUnavailable : Result
    }

    suspend fun check(password: String): Result = withContext(Dispatchers.IO) {
        try {
            val hash = sha1Hex(password).uppercase()
            val prefix = hash.substring(0, 5)
            val suffix = hash.substring(5)

            val conn = URL("https://api.pwnedpasswords.com/range/$prefix")
                .openConnection() as HttpURLConnection
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            conn.setRequestProperty("Add-Padding", "true")
            conn.setRequestProperty("User-Agent", "zule-android/1.0")

            val code = conn.responseCode
            if (code !in 200..299) {
                return@withContext Result.NetworkUnavailable
            }

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val match = body.lineSequence()
                .firstOrNull { it.startsWith(suffix, ignoreCase = true) }
                ?: return@withContext Result.Clean

            val count = match.substringAfter(':').trim().toIntOrNull() ?: 1
            Result.Pwned(count)
        } catch (_: Throwable) {
            Result.NetworkUnavailable
        }
    }

    private fun sha1Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return buildString(bytes.size * 2) {
            for (b in bytes) append("%02x".format(b))
        }
    }
}

class PwnedPasswordException(val breachCount: Int) : RuntimeException(
    "Password appears in $breachCount known breaches.",
)

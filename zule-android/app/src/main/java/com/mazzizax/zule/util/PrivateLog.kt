package com.mazzizax.zule.util

import android.util.Log
import com.mazzizax.zule.BuildConfig

/**
 * Two-channel logger.
 *
 * - `safe()` is always emitted. Use it for class names, HTTP codes, support
 *   refs, non-PII summaries. Proguard preserves these at warning/error level.
 * - `detail()` is gated on `BuildConfig.DEBUG`. Use it when the message may
 *   carry email, user_id, raw JSON, token fragments.
 */
object PrivateLog {

    fun safe(tag: String, message: String, throwable: Throwable? = null) {
        if (throwable == null) Log.e(tag, message) else Log.e(tag, message, throwable)
    }

    fun detail(tag: String, message: String, throwable: Throwable? = null) {
        if (!BuildConfig.DEBUG) return
        if (throwable == null) Log.e(tag, message) else Log.e(tag, message, throwable)
    }

    fun error(tag: String, summary: String, throwable: Throwable) {
        safe(tag, summary)
        detail(tag, throwable.message ?: "(no message)", throwable)
    }
}

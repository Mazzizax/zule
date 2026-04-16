package com.mazzizax.zule.ui.components

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import com.mazzizax.zule.data.SessionManager

/**
 * Wraps the app content and tracks touch events for the inactivity timeout.
 *
 * Translation of the web app's document.addEventListener for
 * ['mousedown', 'keydown', 'scroll', 'touchstart'] that calls
 * resetInactivityTimer() in AuthContext.tsx.
 *
 * On Android, touch is the primary input — we track Press events.
 */
@Composable
fun SessionTimeoutWrapper(
    sessionManager: SessionManager,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .pointerInput(Unit) {
                awaitEachGesture {
                    val event = awaitPointerEvent()
                    if (event.type == PointerEventType.Press) {
                        sessionManager.onUserActivity()
                    }
                }
            },
    ) {
        content()
    }
}

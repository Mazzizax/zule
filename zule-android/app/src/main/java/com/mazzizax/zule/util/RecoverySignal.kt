package com.mazzizax.zule.util

import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Process-scoped signal for "the user just tapped a password-recovery link
 * in their email". Produced by MainActivity's deep-link handler and consumed
 * by the auth ViewModel on the next NotAuthenticated → Authenticated
 * transition, which forces a password-change UX before handing back to the
 * normal app flow.
 *
 * Lives outside the ViewModel because it must survive ViewModel recreation
 * (process restart from deep-link cold-start).
 */
object RecoverySignal {
    val pendingRecovery: MutableStateFlow<Boolean> = MutableStateFlow(false)
}

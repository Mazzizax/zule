package com.mazzizax.zule.ui.components

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.mazzizax.zule.util.RecoveryHint

/**
 * Renders a single action button below an error message, mapped from the
 * RecoveryHint the view model attached to the event. The button label makes
 * the next step explicit — "Re-enrol passkey", "Open device security
 * settings", "Retry with Google Password Manager", "Contact support".
 */
@Composable
fun HintActionRow(
    hint: RecoveryHint?,
    supportRef: String?,
    onAction: (RecoveryHint) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (hint == null) return

    val label = when (hint) {
        RecoveryHint.FORCE_REENROLL -> "Re-enrol passkey"
        RecoveryHint.ALREADY_ENROLLED -> "Use existing passkey"
        RecoveryHint.RETRY_WITH_GOOGLE_PM -> "Open Credential Manager settings"
        RecoveryHint.NEEDS_SCREEN_LOCK -> "Open device security settings"
        RecoveryHint.CONTACT_SUPPORT -> "Contact support"
    }

    Row(modifier = modifier.fillMaxWidth().padding(top = 4.dp)) {
        TextButton(onClick = { onAction(hint) }) { Text(label) }
        if (supportRef != null) {
            Text(
                "ref: $supportRef",
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(start = 8.dp, top = 14.dp),
            )
        }
    }
}

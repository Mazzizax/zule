package com.mazzizax.zule.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent
import com.mazzizax.zule.BuildConfig

/**
 * Privacy · Terms · Contact footer. URLs are BuildConfig fields so host apps
 * can override them at integration time. Each link opens in a Chrome Custom
 * Tab with a toolbar color matching the app surface.
 */
@Composable
fun LegalFooter(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val toolbarColor = MaterialTheme.colorScheme.background.toArgb()
    val open: (String) -> Unit = { url ->
        val intent = CustomTabsIntent.Builder()
            .setDefaultColorSchemeParams(
                CustomTabColorSchemeParams.Builder()
                    .setToolbarColor(toolbarColor)
                    .build(),
            )
            .setShowTitle(true)
            .build()
        runCatching { intent.launchUrl(context, url.toUri()) }
    }

    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.Center,
    ) {
        TextButton(onClick = { open(BuildConfig.LEGAL_PRIVACY_URL) }) {
            Text("Privacy", style = MaterialTheme.typography.labelSmall)
        }
        Text("·", style = MaterialTheme.typography.labelSmall)
        TextButton(onClick = { open(BuildConfig.LEGAL_TERMS_URL) }) {
            Text("Terms", style = MaterialTheme.typography.labelSmall)
        }
        Text("·", style = MaterialTheme.typography.labelSmall)
        TextButton(onClick = { open(BuildConfig.LEGAL_CONTACT_URL) }) {
            Text("Contact", style = MaterialTheme.typography.labelSmall)
        }
    }
}

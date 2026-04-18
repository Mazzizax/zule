package com.mazzizax.zule.data

import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import com.plaid.link.OpenPlaidLink
import com.plaid.link.configuration.LinkTokenConfiguration
import com.plaid.link.result.LinkExit
import com.plaid.link.result.LinkSuccess

/**
 * Plaid Link activity-result holder. Must be constructed before setContent
 * in MainActivity.onCreate — registerForActivityResult requires registration
 * during STARTED, not during a recomposition.
 */
class PlaidLinkHelper(activity: ComponentActivity) {

    private var onSuccess: ((String) -> Unit)? = null
    private var onExit: ((String?) -> Unit)? = null

    val launcher: ActivityResultLauncher<LinkTokenConfiguration> =
        activity.registerForActivityResult(OpenPlaidLink()) { result ->
            when (result) {
                is LinkSuccess -> onSuccess?.invoke(result.publicToken)
                is LinkExit -> onExit?.invoke(result.error?.displayMessage)
            }
        }

    fun openLink(
        linkToken: String,
        onSuccess: (publicToken: String) -> Unit,
        onExit: (error: String?) -> Unit = {},
    ) {
        this.onSuccess = onSuccess
        this.onExit = onExit
        val config = LinkTokenConfiguration.Builder()
            .token(linkToken)
            .build()
        launcher.launch(config)
    }
}

package com.mazzizax.zule.data

import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import com.plaid.link.OpenPlaidLink
import com.plaid.link.configuration.LinkTokenConfiguration
import com.plaid.link.result.LinkExit
import com.plaid.link.result.LinkSuccess

/**
 * Translation of Dashboard.tsx openPlaidLink() Plaid Link widget integration.
 *
 * Web app flow:
 *   1. Plaid.create({ token: link_token, onSuccess, onExit })
 *   2. handler.open()
 *   3. onSuccess(public_token) → exchange token → refresh profile
 *   4. onExit() → stop loading
 *
 * Android equivalent:
 *   1. registerForActivityResult(OpenPlaidLink()) — must happen before setContent in onCreate
 *   2. launcher.launch(LinkTokenConfiguration) — opens Plaid Link Android SDK
 *   3. LinkSuccess → exchange public token → refresh profile
 *   4. LinkExit → stop loading
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

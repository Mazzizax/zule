package com.mazzizax.zule.ui.screen.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.ui.platform.LocalContext
import com.mazzizax.zule.MainActivity
import com.mazzizax.zule.domain.model.PlaidAccount
import com.mazzizax.zule.domain.model.Subscription
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.GunmetalBrush
import com.mazzizax.zule.ui.theme.GunmetalTextColor
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.RoseGoldBrush
import com.mazzizax.zule.ui.theme.RoseGoldTextColor
import com.mazzizax.zule.ui.theme.TitaniumBrush
import com.mazzizax.zule.ui.theme.TitaniumTextColor
import com.mazzizax.zule.ui.theme.ZuleColors

private val SERVICE_DISPLAY_NAME = mapOf(
    "goals" to "Goals",
    "aca" to "Advanced Cognitive Assistant",
)

private val TIER_METAL = mapOf(
    "goals" to mapOf("standard" to "rose", "premium" to "titanium", "citizen" to "gunmetal"),
    "aca" to mapOf("standard" to "rose", "enthusiast" to "titanium", "padawan" to "gunmetal"),
)

private data class MetalStyle(val brush: Brush, val textColor: Color)

private val METAL_STYLES = mapOf(
    "rose" to MetalStyle(RoseGoldBrush, RoseGoldTextColor),
    "titanium" to MetalStyle(TitaniumBrush, TitaniumTextColor),
    "gunmetal" to MetalStyle(GunmetalBrush, GunmetalTextColor),
)

private fun formatDate(dateString: String?): String {
    if (dateString == null) return "N/A"
    return try {
        val instant = java.time.Instant.parse(dateString)
        val localDate = instant.atZone(java.time.ZoneId.systemDefault()).toLocalDate()
        val formatter = java.time.format.DateTimeFormatter.ofPattern("M/d/yyyy")
        localDate.format(formatter)
    } catch (_: Exception) {
        dateString
    }
}

// Status values that trigger the amber update banner
private val UPDATE_STATUSES = listOf("login_required", "pending_expiration", "pending_disconnect")

@Composable
fun DashboardScreen(
    onSignOut: () -> Unit,
    onNavigateToSubscriptions: ((String?) -> Unit)? = null,
    onNavigateToApps: (() -> Unit)? = null,
    onNavigateToFleetAuth: (() -> Unit)? = null,
    onNavigateToLoyalty: (() -> Unit)? = null,
    viewModel: DashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val mainActivity = LocalContext.current as MainActivity

    if (state.isLoading) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(
                    color = ZuleColors.Primary,
                    strokeWidth = 2.dp,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Loading...",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            }
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // ── Account + Subscriptions cards — stacked on mobile ──
        ZuleCard(modifier = Modifier.fillMaxWidth()) {
            CardSectionTitle("Account")
            InfoRow(label = "Email:", value = state.email ?: "")
            InfoRow(label = "Member Since:", value = formatDate(state.memberSince))
            InfoRow(label = "Last Active:", value = formatDate(state.lastActive), showDivider = false)
        }

        Spacer(modifier = Modifier.height(16.dp))

        ZuleCard(modifier = Modifier.fillMaxWidth()) {
            CardSectionTitle("Subscriptions")
            val activeSubs = state.subscriptions.filter { it.status == "active" }
            if (activeSubs.isNotEmpty()) {
                activeSubs.forEach { sub ->
                    SubscriptionRow(
                        subscription = sub,
                        onClick = { onNavigateToSubscriptions?.invoke(sub.serviceId) },
                    )
                }
            } else {
                SubscriptionDefaultRow(
                    onClick = { onNavigateToSubscriptions?.invoke("goals") },
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Connected Accounts (Plaid) ──
        ZuleCard(modifier = Modifier.fillMaxWidth()) {
            CardSectionTitle("Connected Accounts")
            if (state.plaidAccounts.isNotEmpty()) {
                state.plaidAccounts.forEach { acct ->
                    PlaidAccountItem(
                        account = acct,
                        removeLoading = state.removeLoadingId == acct.id,
                        onRemove = { viewModel.removeCard(acct.id) },
                    )
                }
            } else {
                Text(
                    text = "Link your accounts for automated challenge verification and other features.",
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                    lineHeight = 18.sp,
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            ZulePrimaryButton(
                text = if (state.plaidLoading) "Connecting..." else "Link Card",
                enabled = !state.plaidLoading,
                onClick = {
                    viewModel.createLinkToken { linkToken ->
                        mainActivity.plaidLinkHelper.openLink(
                            linkToken = linkToken,
                            onSuccess = { publicToken -> viewModel.exchangePublicToken(publicToken) },
                            onExit = { viewModel.onPlaidExit() },
                        )
                    }
                },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Transaction Pipeline ──
        // Dev-mode Transaction Pipeline — 0.Pull → 1.Mint → 2.Send → 3.Shred.
        if (state.plaidAccounts.isNotEmpty()) {
            ZuleCard(modifier = Modifier.fillMaxWidth()) {
                // Pull Transactions per account
                state.plaidAccounts.forEach { acct ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = acct.institutionName,
                            fontFamily = CormorantGaramond,
                            fontSize = 14.sp,
                            color = ZuleColors.TextSecondary,
                        )
                        Box(
                            modifier = Modifier
                                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                                .clickable(enabled = state.pullLoadingId == null) {
                                    viewModel.pullTransactions(acct.id)
                                }
                                .padding(horizontal = 14.dp, vertical = 6.dp),
                        ) {
                            Text(
                                text = if (state.pullLoadingId == acct.id) "..." else "Pull Transactions",
                                fontFamily = CormorantGaramond,
                                fontWeight = FontWeight.W500,
                                fontSize = 14.sp,
                                letterSpacing = 0.84.sp,
                                color = ZuleColors.TextSecondary,
                            )
                        }
                    }
                }

                if (state.pullResult != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = state.pullResult!!, fontFamily = CormorantGaramond, fontSize = 13.sp, color = ZuleColors.TextSecondary)
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Phase 1 — mint card_attestation from unminted transactions.
                ZulePrimaryButton(
                    text = if (state.analyzeLoading) "Minting..." else "1. Mint cards",
                    enabled = !state.analyzeLoading,
                    onClick = { viewModel.mintCards() },
                )

                if (state.analyzeResult != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = state.analyzeResult!!, fontFamily = CormorantGaramond, fontSize = 13.sp, color = ZuleColors.TextSecondary)
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Phase 2 — hand the attestation to Vinzrik via deep link.
                ZulePrimaryButton(
                    text = "2. Send to Vinzrik",
                    enabled = state.lastAttestation != null,
                    onClick = {
                        val uri = viewModel.vinzrikPushUri() ?: return@ZulePrimaryButton
                        runCatching {
                            mainActivity.startActivity(
                                android.content.Intent(android.content.Intent.ACTION_VIEW, uri)
                            )
                            viewModel.noteSentToVinzrik()
                        }.onFailure {
                            // Vinzrik not installed — ActivityNotFoundException
                        }
                    },
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Phase 3 — purge raw transactions on zule's side.
                ZulePrimaryButton(
                    text = if (state.shredLoading) "Shredding..." else "3. Shred raw",
                    enabled = !state.shredLoading,
                    onClick = { viewModel.shredRaw() },
                )

                if (state.shredResult != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = state.shredResult!!, fontFamily = CormorantGaramond, fontSize = 13.sp, color = ZuleColors.TextSecondary)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        // ── App Connections ──
        ZuleCard(modifier = Modifier.fillMaxWidth()) {
            CardSectionTitle("App Connections")
            Text(
                text = "Connect your daily use apps here. Don't see an app you use? Let us know and we'll see what we can do.",
                fontFamily = CormorantGaramond,
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
                lineHeight = 18.sp,
            )
            Spacer(modifier = Modifier.height(16.dp))
            ZulePrimaryButton(
                text = "Manage Apps",
                onClick = { onNavigateToApps?.invoke() },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Loyalty Programs ──
        ZuleCard(modifier = Modifier.fillMaxWidth()) {
            CardSectionTitle("Loyalty Programs")
            Text(
                text = "Enter your loyalty member numbers for automated rewards tracking. Scan barcodes from your phone for quick entry.",
                fontFamily = CormorantGaramond,
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
                lineHeight = 18.sp,
            )
            Spacer(modifier = Modifier.height(16.dp))
            ZulePrimaryButton(
                text = "Manage Loyalty Cards",
                onClick = { onNavigateToLoyalty?.invoke() },
            )
        }

        // ── Fleet Auth (mobile-only) ──
        if (onNavigateToFleetAuth != null) {
            Spacer(modifier = Modifier.height(16.dp))
            ZuleCard(modifier = Modifier.fillMaxWidth()) {
                CardSectionTitle("Fleet Auth")
                Text(
                    text = "Approve or deny login requests from your fleet machines.",
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                    lineHeight = 18.sp,
                )
                Spacer(modifier = Modifier.height(16.dp))
                ZulePrimaryButton(
                    text = "Auth Requests",
                    onClick = { onNavigateToFleetAuth.invoke() },
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

// ── Reusable Components ──

/**
 * Card wrapper matching .card CSS:
 *   background: var(--bg-card) (#111010)
 *   border: 1px solid var(--border) (#1e1b18)
 *   border-radius: 4px
 *   padding: 24px
 */
@Composable
private fun ZuleCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier
            .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(24.dp),
    ) {
        content()
    }
}

/**
 * Card section title matching .card h2 CSS:
 *   font-size: 11px
 *   font-weight: 600
 *   text-transform: uppercase
 *   letter-spacing: 3px
 *   color: var(--zule-gold-dim)
 *   font-family: Cormorant Garamond
 */
@Composable
private fun CardSectionTitle(title: String) {
    Text(
        text = title.uppercase(),
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W600,
        fontSize = 11.sp,
        letterSpacing = 3.sp,
        color = ZuleColors.PrimaryDim,
    )
    Spacer(modifier = Modifier.height(16.dp))
}

/**
 * Info row matching .info-row CSS:
 *   display: flex, justify-content: space-between
 *   padding: 10px 0
 *   border-bottom: 1px solid var(--border)
 *   .label: color var(--text-secondary)
 *   .value: color var(--text-primary)
 */
@Composable
private fun InfoRow(
    label: String,
    value: String,
    showDivider: Boolean = true,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextSecondary,
        )
        Text(
            text = value,
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
    if (showDivider) {
        HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
    }
}

@Composable
private fun SubscriptionRow(
    subscription: Subscription,
    onClick: () -> Unit,
) {
    val metalKey = TIER_METAL[subscription.serviceId]?.get(subscription.tier) ?: "rose"
    val metal = METAL_STYLES[metalKey] ?: METAL_STYLES["rose"]!!

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = SERVICE_DISPLAY_NAME[subscription.serviceId] ?: subscription.serviceId,
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextSecondary,
        )
        MetallicBadge(
            text = subscription.tier,
            brush = metal.brush,
            textColor = metal.textColor,
            onClick = onClick,
        )
    }
    HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
}

/**
 * Default subscription row showing citizen/gunmetal badge for Goals.
 */
@Composable
private fun SubscriptionDefaultRow(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Goals",
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextSecondary,
        )
        MetallicBadge(
            text = "citizen",
            brush = GunmetalBrush,
            textColor = GunmetalTextColor,
            onClick = onClick,
        )
    }
    HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
}

/** Metallic tier badge — brush/text color chosen from TIER_METAL. */
@Composable
private fun MetallicBadge(
    text: String,
    brush: Brush,
    textColor: Color,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .width(120.dp)
            .clip(RoundedCornerShape(4.dp))
            .background(brush)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text.uppercase(),
            fontFamily = CormorantGaramond,
            fontWeight = FontWeight.W600,
            fontSize = 12.sp,
            letterSpacing = 1.7.sp, // 0.14em
            color = textColor,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun PlaidAccountItem(
    account: PlaidAccount,
    removeLoading: Boolean,
    onRemove: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .border(1.dp, Color(0xFF222222), RoundedCornerShape(4.dp))
            .padding(8.dp),
    ) {
        // Institution name + connected date
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = account.institutionName,
                fontFamily = CormorantGaramond,
                fontSize = 16.sp,
                color = ZuleColors.TextSecondary,
            )
            Text(
                text = formatDate(account.connectedAt),
                fontFamily = CormorantGaramond,
                fontSize = 11.sp,
                color = ZuleColors.TextSecondary.copy(alpha = 0.5f),
            )
        }

        if (account.status == "new_accounts_available") {
            Spacer(modifier = Modifier.height(4.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0x203B82F6), RoundedCornerShape(4.dp))
                    .border(1.dp, Color(0x403B82F6), RoundedCornerShape(4.dp))
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "New accounts available at this institution",
                    fontFamily = CormorantGaramond,
                    fontSize = 11.sp,
                    color = Color(0xFF3B82F6),
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .border(1.dp, Color(0xFF3B82F6), RoundedCornerShape(4.dp))
                        .clickable { /* Plaid update accounts flow */ }
                        .padding(horizontal = 10.dp, vertical = 3.dp),
                ) {
                    Text(
                        text = "Add Accounts",
                        fontFamily = CormorantGaramond,
                        fontSize = 11.sp,
                        color = Color(0xFF3B82F6),
                    )
                }
            }
        }

        if (account.status != null && UPDATE_STATUSES.contains(account.status)) {
            Spacer(modifier = Modifier.height(4.dp))
            val statusText = when (account.status) {
                "login_required" -> "Login required \u2014 re-authenticate to continue"
                "pending_expiration" -> "Access expiring \u2014 re-authenticate to renew"
                else -> "Pending disconnect \u2014 re-authenticate to maintain access"
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0x20F59E0B), RoundedCornerShape(4.dp))
                    .border(1.dp, Color(0x40F59E0B), RoundedCornerShape(4.dp))
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = statusText,
                    fontFamily = CormorantGaramond,
                    fontSize = 11.sp,
                    color = Color(0xFFF59E0B),
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .border(1.dp, Color(0xFFF59E0B), RoundedCornerShape(4.dp))
                        .clickable { /* Plaid update link flow */ }
                        .padding(horizontal = 10.dp, vertical = 3.dp),
                ) {
                    Text(
                        text = "Update",
                        fontFamily = CormorantGaramond,
                        fontSize = 11.sp,
                        color = Color(0xFFF59E0B),
                    )
                }
            }
        }

        // Remove button
        Spacer(modifier = Modifier.height(6.dp))
        Box(
            modifier = Modifier
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .clickable(enabled = !removeLoading, onClick = onRemove)
                .padding(horizontal = 14.dp, vertical = 6.dp),
        ) {
            Text(
                text = if (removeLoading) "..." else "Remove",
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W500,
                fontSize = 14.sp,
                letterSpacing = 0.84.sp, // 0.06em
                color = ZuleColors.TextSecondary,
            )
        }
    }
}

/**
 * Primary button matching .btn-primary CSS:
 *   background: metallic gradient (MetalSurfaceBrush)
 *   font: Cormorant Garamond 18px weight 500
 *   color: var(--bg-deep) (#080706)
 *   border-radius: 4px
 *   full width
 */
@Composable
private fun ZulePrimaryButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp),
        shape = RoundedCornerShape(4.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Transparent,
            disabledContainerColor = Color.Transparent,
        ),
        enabled = enabled,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    if (enabled) MetalSurfaceBrush
                    else Brush.linearGradient(
                        listOf(ZuleColors.TextMuted, ZuleColors.TextMuted),
                    ),
                    RoundedCornerShape(4.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = text,
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W500,
                    fontSize = 18.sp,
                    color = ZuleColors.Background,
                ),
            )
        }
    }
}

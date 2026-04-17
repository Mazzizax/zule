package com.mazzizax.zule.ui.screen.subscriptions

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.GunmetalBrush
import com.mazzizax.zule.ui.theme.GunmetalTextColor
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.RoseGoldBrush
import com.mazzizax.zule.ui.theme.RoseGoldTextColor
import com.mazzizax.zule.ui.theme.TitaniumBrush
import com.mazzizax.zule.ui.theme.TitaniumTextColor
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Translation of pages/Subscriptions.tsx (498 lines).
 *
 * Two views:
 * 1. Service list — five clickable cards
 * 2. Tier detail — back button, service name, tier grid with metallic buttons
 *
 * Checkout: Custom Chrome Tab (not popup).
 * Upgrade: inline confirmation.
 * Cancel: inline confirmation with checkbox. Goals cannot be cancelled.
 *
 * Hardcoded tier data exactly matches the web source including
 * stripe_price_ids, product_ids, limits, and features arrays.
 */

// ── Data structures matching Subscriptions.tsx ──

data class ServiceTier(
    val id: String,
    val name: String,
    val metal: String,
    val price: String?,
    val stripePriceId: String?,
    val productId: String? = null,
    val mode: String = "subscription",
    val limit: Int? = null,
    val features: List<String>,
)

data class Service(
    val id: String,
    val name: String,
    val description: String,
    val tiers: List<ServiceTier>,
)

// Exact service/tier data from Subscriptions.tsx lines 57-107
val services = listOf(
    Service(
        id = "conversations-with-xenon",
        name = "Conversations with Xenon",
        description = "A novel novel",
        tiers = listOf(
            ServiceTier(id = "sage_relic", name = "Sage Relic", metal = "rose", price = null, stripePriceId = null, mode = "payment", features = emptyList()),
            ServiceTier(id = "founder_account", name = "Founder Account", metal = "rose", price = null, stripePriceId = null, mode = "payment", features = emptyList()),
            ServiceTier(id = "novel_chapter", name = "Novel Chapter", metal = "rose", price = null, stripePriceId = null, mode = "payment", features = emptyList()),
        ),
    ),
    Service(
        id = "iterations",
        name = "Iterations",
        description = "The game that evolves when you do",
        tiers = listOf(
            ServiceTier(id = "secret_door_key", name = "Secret Door Key", metal = "rose", price = "$5", stripePriceId = "price_1Sui0sDRpCHsf7Inh8xp45BV", productId = "secret_door_key", mode = "payment", limit = 33, features = listOf("Secret Door Key 3-Pack")),
            ServiceTier(id = "need_more_data", name = "Need More Data", metal = "rose", price = "$10", stripePriceId = "price_1Sui3qDRpCHsf7Inqw16CsUk", productId = "need_more_data", mode = "payment", limit = 5, features = listOf("Replay Iterations phases 1-4")),
            ServiceTier(id = "dragon_eye", name = "Dragon Eye", metal = "rose", price = "$500", stripePriceId = "price_1Sui7tDRpCHsf7InSpqU9Bu7", productId = "dragon_eye", mode = "payment", limit = 1, features = listOf("One per account")),
        ),
    ),
    Service(
        id = "aca",
        name = "Advanced Cognitive Assistant",
        description = "4 frontier AI models arguing over your daily life",
        tiers = listOf(
            ServiceTier(id = "standard", name = "Standard", metal = "rose", price = "$65/mo", stripePriceId = "price_1SuhgaDRpCHsf7InZqtoYRA3", features = emptyList()),
            ServiceTier(id = "enthusiast", name = "Enthusiast", metal = "titanium", price = "$125/mo", stripePriceId = "price_1SuhqgDRpCHsf7InpPL2w5d9", features = emptyList()),
            ServiceTier(id = "padawan", name = "Padawan", metal = "gunmetal", price = "$215/mo", stripePriceId = "price_1SuhvuDRpCHsf7In7c52Ovn1", features = emptyList()),
        ),
    ),
    Service(
        id = "hardware",
        name = "Hardware",
        description = "Custom crafted equipment to elevate your daily life",
        tiers = listOf(
            ServiceTier(id = "axe_s", name = "AXE S", metal = "rose", price = null, stripePriceId = null, mode = "payment", features = emptyList()),
            ServiceTier(id = "torch", name = "TORCH", metal = "rose", price = null, stripePriceId = null, mode = "payment", features = emptyList()),
        ),
    ),
    Service(
        id = "goals",
        name = "Goals",
        description = "Goal Oriented Adventure Living System",
        tiers = listOf(
            ServiceTier(id = "standard", name = "Standard", metal = "rose", price = null, stripePriceId = null, features = listOf("Basic XP tracking", "5 gear slots", "Community quests")),
            ServiceTier(id = "premium", name = "Premium", metal = "titanium", price = null, stripePriceId = null, features = listOf("Full XP tracking", "All 20 gear slots", "Loadouts", "Sponsor pools", "Priority quest matching")),
            ServiceTier(id = "citizen", name = "Citizen", metal = "gunmetal", price = null, stripePriceId = null, features = listOf("Everything in Premium", "Advanced analytics", "Custom loadout themes", "Early access features", "Direct brand engagement")),
        ),
    ),
)

// ── Metal styling helpers ──

/**
 * Returns the Brush, text color, border color, and highlight color for a metal name.
 * Matches the metals object in Subscriptions.tsx lines 8-30.
 */
private data class MetalStyle(
    val brush: Brush,
    val textColor: Color,
    val borderColor: Color,
    val highlightColor: Color,
)

private fun metalStyleFor(metal: String): MetalStyle = when (metal) {
    "titanium" -> MetalStyle(
        brush = TitaniumBrush,
        textColor = TitaniumTextColor,
        borderColor = Color(0x66CFD8DC),  // rgba(207,216,220,0.4)
        highlightColor = Color(0x80CFD8DC),  // rgba(207,216,220,0.5)
    )
    "gunmetal" -> MetalStyle(
        brush = GunmetalBrush,
        textColor = GunmetalTextColor,
        borderColor = Color(0x806E747C),  // rgba(110,116,124,0.5)
        highlightColor = Color(0x59A0A6AE),  // rgba(160,166,174,0.35)
    )
    else -> MetalStyle(
        brush = RoseGoldBrush,
        textColor = RoseGoldTextColor,
        borderColor = Color(0x66E0D0B8),  // rgba(224,208,184,0.4)
        highlightColor = Color(0x66E0D0B8),  // rgba(224,208,184,0.4)
    )
}

// ── Helper: open Custom Chrome Tab ──

private fun openCustomTab(context: Context, url: String) {
    val intent = CustomTabsIntent.Builder().build()
    intent.launchUrl(context, Uri.parse(url))
}

// ── Main Screen ──

@Composable
fun SubscriptionsScreen(
    viewModel: SubscriptionsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    val selectedService = state.selectedServiceId?.let { id -> services.find { it.id == id } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        if (selectedService == null) {
            ServiceList(
                onServiceClick = { serviceId -> viewModel.selectService(serviceId) },
            )
        } else {
            TierDetail(
                service = selectedService,
                state = state,
                viewModel = viewModel,
                context = context,
                onBack = { viewModel.selectService(null) },
            )
        }
    }
}

// ── Service List View ──

@Composable
private fun ServiceList(
    onServiceClick: (String) -> Unit,
) {
    services.forEach { svc ->
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(ZuleColors.Surface)
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .clickable { onServiceClick(svc.id) }
                .padding(16.dp),
        ) {
            Column {
                // Service name: metallic gradient uppercase Cormorant Garamond
                // matches style={{ fontFamily: g, fontSize: '22px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase' }}
                Text(
                    text = svc.name.uppercase(),
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W400,
                        fontSize = 22.sp,
                        letterSpacing = (22 * 0.12).sp,
                        brush = MetalTextBrush,
                    ),
                )
                Spacer(modifier = Modifier.height(4.dp))
                // Description: opacity 0.6, 13px
                Text(
                    text = svc.description,
                    style = TextStyle(
                        fontSize = 13.sp,
                        color = ZuleColors.TextPrimary.copy(alpha = 0.6f),
                    ),
                )
            }
        }
    }
}

// ── Tier Detail View ──

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TierDetail(
    service: Service,
    state: SubscriptionsUiState,
    viewModel: SubscriptionsViewModel,
    context: Context,
    onBack: () -> Unit,
) {
    // "All Services" back button — matches btn-secondary
    OutlinedButton(
        onClick = onBack,
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = ZuleColors.TextSecondary,
        ),
        border = androidx.compose.foundation.BorderStroke(1.dp, ZuleColors.Border),
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier.padding(bottom = 16.dp),
    ) {
        Text(
            text = "All Services",
            fontFamily = CormorantGaramond,
            fontSize = 14.sp,
        )
    }

    // Service name: metallic uppercase 24px
    Text(
        text = service.name.uppercase(),
        style = TextStyle(
            fontFamily = CormorantGaramond,
            fontWeight = FontWeight.W400,
            fontSize = 24.sp,
            letterSpacing = (24 * 0.12).sp,
            brush = MetalTextBrush,
        ),
        modifier = Modifier.padding(bottom = 16.dp),
    )

    // Tier cards — stacked vertically on mobile
    service.tiers.forEach { tier ->
        TierCard(
            service = service,
            tier = tier,
            state = state,
            viewModel = viewModel,
            context = context,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(12.dp))
    }

    // ── Upgrade confirmation inline ──
    val upgradeTarget = state.upgradeTarget
    if (upgradeTarget != null && upgradeTarget.serviceId == service.id) {
        Spacer(modifier = Modifier.height(24.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, ZuleColors.Primary, RoundedCornerShape(6.dp))
                .padding(16.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                // "Switch to <tierName> ($price)? Your card on file will be billed."
                Text(
                    text = buildString {
                        append("Switch to ")
                        append(upgradeTarget.tierName)
                        if (upgradeTarget.price.isNotEmpty()) {
                            append(" (${upgradeTarget.price})")
                        }
                        append("? Your card on file will be billed.")
                    },
                    fontSize = 14.sp,
                    color = ZuleColors.TextPrimary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                Row {
                    // Confirm button
                    Button(
                        onClick = { viewModel.confirmUpgrade() },
                        enabled = !state.upgradeLoading,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ZuleColors.Primary,
                            contentColor = Color(0xFF111111),
                        ),
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(
                            text = if (state.upgradeLoading) "Switching..." else "Confirm",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.W600,
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    // Never Mind button
                    OutlinedButton(
                        onClick = { viewModel.dismissUpgrade() },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = ZuleColors.TextSecondary,
                        ),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF444444)),
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(text = "Never Mind", fontSize = 13.sp)
                    }
                }
            }
        }
    }

    // ── Cancel subscription button ──
    val activeSub = viewModel.getActiveSubscription(service.id)
    val isGoals = service.id == "goals"

    if (!isGoals && activeSub != null && !state.cancelConfirm) {
        Spacer(modifier = Modifier.height(24.dp))
        Box(
            modifier = Modifier.fillMaxWidth(),
            contentAlignment = Alignment.Center,
        ) {
            OutlinedButton(
                onClick = { viewModel.showCancelConfirm() },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color(0xFFEF4444),
                ),
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFEF4444)),
                shape = RoundedCornerShape(4.dp),
            ) {
                Text(text = "Cancel Subscription", fontSize = 13.sp)
            }
        }
    }

    // ── Cancel confirmation inline with checkbox ──
    if (!isGoals && state.cancelConfirm) {
        Spacer(modifier = Modifier.height(24.dp))
        var cancelChecked by remember { mutableStateOf(false) }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFEF4444), RoundedCornerShape(6.dp))
                .padding(16.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .clickable { cancelChecked = !cancelChecked }
                        .padding(bottom = 12.dp),
                ) {
                    Checkbox(
                        checked = cancelChecked,
                        onCheckedChange = { cancelChecked = it },
                        colors = CheckboxDefaults.colors(
                            checkedColor = Color(0xFFEF4444),
                            uncheckedColor = ZuleColors.TextSecondary,
                        ),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "I want to cancel my ${service.name} subscription",
                        fontSize = 13.sp,
                        color = ZuleColors.TextPrimary,
                    )
                }
                Row {
                    // Confirm Cancellation button
                    Button(
                        onClick = {
                            if (cancelChecked) {
                                viewModel.confirmCancel(service.id)
                            }
                        },
                        enabled = !state.cancelLoading,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFFEF4444),
                            contentColor = Color.White,
                        ),
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(
                            text = if (state.cancelLoading) "Canceling..." else "Confirm Cancellation",
                            fontSize = 13.sp,
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    // Never Mind button
                    OutlinedButton(
                        onClick = { viewModel.dismissCancelConfirm() },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = ZuleColors.TextSecondary,
                        ),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF444444)),
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(text = "Never Mind", fontSize = 13.sp)
                    }
                }
            }
        }
    }
}

// ── Individual Tier Card ──

@Composable
private fun TierCard(
    service: Service,
    tier: ServiceTier,
    state: SubscriptionsUiState,
    viewModel: SubscriptionsViewModel,
    context: Context,
    modifier: Modifier = Modifier,
) {
    val metalStyle = metalStyleFor(tier.metal)
    val activeSub = viewModel.getActiveSubscription(service.id)
    val isActive = activeSub?.tier == tier.id
    val isGoals = service.id == "goals"
    val isOneTime = tier.mode == "payment"
    val hasExisting = activeSub != null
    val purchaseCount = viewModel.getPurchaseCount(tier.productId)
    val atLimit = tier.limit != null && purchaseCount >= tier.limit
    val canChange = tier.stripePriceId != null && !isActive
    val loadingKey = "${service.id}-${tier.stripePriceId}"

    // Button label logic — exact match of Subscriptions.tsx lines 374-379
    val label = when {
        isGoals -> "Purchased"
        isOneTime && atLimit -> "Owned"
        isOneTime -> "Purchase"
        isActive -> "Active"
        hasExisting && canChange -> "Switch"
        else -> "Subscribe"
    }

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(4.dp))
            .background(ZuleColors.Surface)
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(16.dp),
    ) {
        // Tier name: metallic text, 20px, 0.08em letter spacing
        Text(
            text = tier.name,
            style = TextStyle(
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W400,
                fontSize = 20.sp,
                letterSpacing = (20 * 0.08).sp,
                brush = MetalTextBrush,
            ),
        )

        // Price if applicable
        if (tier.price != null) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = tier.price,
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W500,
                fontSize = 18.sp,
                color = ZuleColors.Primary,
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Feature bullets — 12px, opacity 0.7
        tier.features.forEach { feature ->
            Text(
                text = feature,
                fontSize = 12.sp,
                color = ZuleColors.TextPrimary.copy(alpha = 0.7f),
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }

        // Pack availability count — shown when limit > 1
        // Web: "{remaining}/{limit} packs available"
        if (tier.limit != null && tier.limit > 1) {
            val remaining = tier.limit - purchaseCount
            Text(
                text = "$remaining/${tier.limit} packs available",
                fontSize = 12.sp,
                color = ZuleColors.TextPrimary.copy(alpha = 0.7f),
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Metallic action button
        val isLoading = state.checkoutLoadingKey == loadingKey
        val isClickable = (canChange || (isOneTime && !atLimit)) && !isLoading

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .background(metalStyle.brush)
                .then(
                    if (isClickable) {
                        Modifier.clickable {
                            if (isOneTime && !atLimit && tier.stripePriceId != null) {
                                viewModel.subscribe(
                                    serviceId = service.id,
                                    stripePriceId = tier.stripePriceId,
                                    productId = tier.productId,
                                    mode = "payment",
                                    onCheckoutUrl = { url -> openCustomTab(context, url) },
                                )
                            } else if (canChange && tier.stripePriceId != null) {
                                if (hasExisting) {
                                    viewModel.showUpgradeConfirmation(
                                        UpgradeTarget(
                                            serviceId = service.id,
                                            tierId = tier.id,
                                            tierName = tier.name,
                                            priceId = tier.stripePriceId,
                                            price = tier.price ?: "",
                                        ),
                                    )
                                } else {
                                    viewModel.subscribe(
                                        serviceId = service.id,
                                        stripePriceId = tier.stripePriceId,
                                        onCheckoutUrl = { url -> openCustomTab(context, url) },
                                    )
                                }
                            }
                        }
                    } else {
                        Modifier
                    }
                )
                .padding(vertical = 10.dp, horizontal = 12.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (isLoading) "Processing..." else label,
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W600,
                fontSize = 12.sp,
                letterSpacing = (12 * 0.14).sp,
                color = metalStyle.textColor.copy(alpha = if (isLoading) 0.6f else 1f),
                textAlign = TextAlign.Center,
            )
        }
    }
}

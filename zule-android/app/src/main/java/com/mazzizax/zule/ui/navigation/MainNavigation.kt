package com.mazzizax.zule.ui.navigation

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.ui.draw.drawBehind
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.mazzizax.zule.R
import com.mazzizax.zule.ui.screen.apps.AppsScreen
import com.mazzizax.zule.ui.screen.machineauth.AuthRequestsScreen
import com.mazzizax.zule.ui.screen.dashboard.DashboardScreen
import com.mazzizax.zule.ui.screen.loyalty.LoyaltyScreen
import com.mazzizax.zule.ui.screen.profile.ProfileScreen
import com.mazzizax.zule.ui.screen.security.SecurityScreen
import com.mazzizax.zule.ui.screen.subscriptions.SubscriptionsScreen
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.SpaceMono
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Kotlin + Jetpack Compose translation of Layout.tsx
 *
 * The web app's mobile view: fixed top header with Zule icon + ZULE metallic title + hamburger,
 * slide-in overlay menu from the right with 4 nav links (Dashboard, Identity, Security, Services)
 * and Sign Out. Sticky "Zero-knowledge User License Enclave" header above content.
 *
 * The four SVG icons from the web app are referenced as vector drawables:
 *   ic_nav_dashboard (compass rose)
 *   ic_nav_identity (dragon)
 *   ic_nav_security (shuriken)
 *   ic_nav_services (gem)
 *   ic_signout (fire dragon)
 * These must be created as Android vector drawables from the original SVG path data.
 */

data class NavItem(
    val route: String,
    val label: String,
    val iconRes: Int,
)

// Exact nav items from Layout.tsx navItems array
val navItems = listOf(
    NavItem("dashboard", "Dashboard", R.drawable.ic_nav_dashboard),
    NavItem("profile", "Identity", R.drawable.ic_nav_identity),
    NavItem("security", "Security", R.drawable.ic_nav_security),
    NavItem("subscriptions", "Services", R.drawable.ic_nav_services),
)

@Composable
fun MainNavigation(
    userEmail: String,
    onSignOut: () -> Unit,
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route
    var menuOpen by remember { mutableStateOf(false) }

    Box(modifier = Modifier.fillMaxSize().background(ZuleColors.Background)) {
        Column(modifier = Modifier.fillMaxSize()) {
            // ── Mobile Header ──
            // Matches .mobile-header: fixed top bar, 56px height, #0f0e0c background
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .background(Color(0xFF0F0E0C))
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                // Left: icon + ZULE title
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Zule icon — 28x28, rounded 6dp, matches .mobile-brand .brand-icon
                    Image(
                        painter = painterResource(R.mipmap.ic_launcher),
                        contentDescription = null,
                        modifier = Modifier.size(28.dp),
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    // ZULE in metallic gradient, 16px, letter-spacing 4px
                    // matches .mobile-header h1
                    Text(
                        text = "ZULE",
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W400,
                        fontSize = 16.sp,
                        letterSpacing = 4.sp,
                        style = androidx.compose.ui.text.TextStyle(
                            brush = MetalTextBrush,
                        ),
                    )
                }
                // Right: hamburger button
                // matches .mobile-menu-btn: 24px font size
                IconButton(onClick = { menuOpen = !menuOpen }) {
                    Text(
                        text = if (menuOpen) "\u2715" else "\u2630",
                        color = ZuleColors.TextPrimary,
                        fontSize = 24.sp,
                    )
                }
            }

            // ── Divider matching border-bottom: 1px solid var(--border) ──
            HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)

            // ── Sticky header: "Zero-knowledge User License Enclave" ──
            // matches the sticky div in main-content with metallic initials
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(ZuleColors.Background, Color.Transparent),
                            startY = 0f,
                            endY = 200f,
                        )
                    )
                    .padding(horizontal = 20.dp, vertical = 16.dp),
            ) {
                // The header interleaves large metallic initials with small monospace words
                // fontSize 12px for words, 28px for initials, letterSpacing 0.18em
                Text(
                    text = buildAnnotatedString {
                        val initialStyle = SpanStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W400,
                            fontSize = 28.sp,
                            letterSpacing = 1.sp,
                            brush = MetalTextBrush,
                        )
                        val wordStyle = SpanStyle(
                            fontFamily = SpaceMono,
                            fontWeight = FontWeight.W300,
                            fontSize = 12.sp,
                            letterSpacing = 2.sp,
                            color = ZuleColors.PrimaryDim,
                        )
                        withStyle(initialStyle) { append("Z") }
                        withStyle(wordStyle) { append("ero-knowledge ") }
                        withStyle(initialStyle) { append("U") }
                        withStyle(wordStyle) { append("ser ") }
                        withStyle(initialStyle) { append("L") }
                        withStyle(wordStyle) { append("icense ") }
                        withStyle(initialStyle) { append("E") }
                        withStyle(wordStyle) { append("nclave") }
                    },
                )
            }

            // ── Main content area ──
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 20.dp),
            ) {
                NavHost(
                    navController = navController,
                    startDestination = "dashboard",
                ) {
                    composable("dashboard") {
                        DashboardScreen(
                            onSignOut = onSignOut,
                            onNavigateToSubscriptions = { serviceId ->
                                navController.navigate("subscriptions")
                            },
                            onNavigateToApps = {
                                navController.navigate("apps")
                            },
                            onNavigateToLoyalty = {
                                navController.navigate("loyalty")
                            },
                            onNavigateToFleetAuth = {
                                navController.navigate("fleet-auth")
                            },
                        )
                    }
                    composable("profile") { ProfileScreen() }
                    composable("security") { SecurityScreen(onSignOut = onSignOut) }
                    composable("subscriptions") { SubscriptionsScreen() }
                    composable("apps") { AppsScreen() }
                    composable("loyalty") { LoyaltyScreen() }
                    composable("fleet-auth") { AuthRequestsScreen() }
                }
            }
        }

        // ── Menu Overlay ──
        // matches .mobile-menu-overlay: position fixed, rgba(0,0,0,0.8) background
        // menu slides in from right, 280px wide, #0f0e0c background
        AnimatedVisibility(
            visible = menuOpen,
            enter = fadeIn(),
            exit = fadeOut(),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color(0xCC000000))
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                    ) { menuOpen = false },
            ) {
                AnimatedVisibility(
                    visible = menuOpen,
                    enter = slideInHorizontally(initialOffsetX = { it }),
                    exit = slideOutHorizontally(targetOffsetX = { it }),
                    modifier = Modifier.align(Alignment.CenterEnd),
                ) {
                    Column(
                        modifier = Modifier
                            .width(280.dp)
                            .fillMaxHeight()
                            .background(Color(0xFF0F0E0C))
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                            ) { /* consume clicks so overlay doesn't close */ },
                    ) {
                        // ── Menu header: user email ──
                        // matches .mobile-menu-header: padding 20px, border-bottom
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(20.dp),
                        ) {
                            Text(
                                text = userEmail,
                                fontFamily = SpaceMono,
                                fontSize = 13.sp,
                                color = ZuleColors.TextSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)

                        // ── Nav links ──
                        // matches .mobile-nav-links: padding 16px 12px
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 12.dp, vertical = 16.dp),
                        ) {
                            navItems.forEach { item ->
                                val isActive = currentRoute == item.route
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .then(
                                            if (isActive) {
                                                // matches .nav-link.active:
                                                // border-left 2px gold, gold background glow
                                                Modifier
                                                    .background(
                                                        Color(0x1FC4A882),
                                                        RoundedCornerShape(4.dp),
                                                    )
                                                    .drawBehind {
                                                        drawRect(
                                                            color = ZuleColors.Primary,
                                                            topLeft = androidx.compose.ui.geometry.Offset.Zero,
                                                            size = androidx.compose.ui.geometry.Size(2.dp.toPx(), size.height),
                                                        )
                                                    }
                                            } else {
                                                Modifier
                                            }
                                        )
                                        .clickable {
                                            navController.navigate(item.route) {
                                                popUpTo(navController.graph.startDestinationId) {
                                                    saveState = true
                                                }
                                                launchSingleTop = true
                                                restoreState = true
                                            }
                                            menuOpen = false
                                        }
                                        .padding(horizontal = 16.dp, vertical = 11.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Icon(
                                        painter = painterResource(item.iconRes),
                                        contentDescription = item.label,
                                        modifier = Modifier.size(18.dp),
                                        tint = if (isActive) ZuleColors.Primary else ZuleColors.TextSecondary,
                                    )
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Text(
                                        text = item.label,
                                        fontFamily = CormorantGaramond,
                                        fontWeight = FontWeight.W400,
                                        fontSize = 16.sp,
                                        letterSpacing = 1.3.sp,
                                        color = if (isActive) ZuleColors.Primary else ZuleColors.TextSecondary,
                                    )
                                }
                                Spacer(modifier = Modifier.height(2.dp))
                            }
                        }

                        // ── Menu footer: Sign Out ──
                        // matches .mobile-menu-footer: padding 16px, border-top
                        HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    menuOpen = false
                                    onSignOut()
                                }
                                .padding(16.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center,
                            ) {
                                Icon(
                                    painter = painterResource(R.drawable.ic_signout),
                                    contentDescription = "Sign Out",
                                    modifier = Modifier.size(16.dp),
                                    tint = ZuleColors.TextMuted,
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Sign Out",
                                    fontFamily = CormorantGaramond,
                                    fontWeight = FontWeight.W500,
                                    fontSize = 16.sp,
                                    letterSpacing = 1.sp,
                                    color = ZuleColors.TextMuted,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

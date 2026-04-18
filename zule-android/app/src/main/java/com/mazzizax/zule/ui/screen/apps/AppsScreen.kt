package com.mazzizax.zule.ui.screen.apps

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.ZuleColors

private data class AppInfo(
    val id: String,
    val name: String,
    val description: String,
    val icon: String,
)

private val apps = listOf(
    AppInfo(
        id = "samsung-health",
        name = "Samsung Health",
        description = "Steps, workouts, sleep, and heart rate data from Samsung Health",
        icon = "\u2764\uFE0F\u200D\uD83D\uDD25",  // heart-fire emoji
    ),
    AppInfo(
        id = "playstation",
        name = "PlayStation",
        description = "Trophy data, game activity, and playtime from PlayStation Network",
        icon = "\uD83C\uDFAE",  // gamepad emoji
    ),
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AppsScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // "App Connections" metallic uppercase title
        // matches style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase' }}
        Text(
            text = "APP CONNECTIONS",
            style = TextStyle(
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W400,
                fontSize = 24.sp,
                letterSpacing = (24 * 0.12).sp,
                brush = MetalTextBrush,
            ),
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Subtitle — opacity 0.5, 13px
        Text(
            text = "Connect your daily use apps for automated challenge verification and other features.",
            fontSize = 13.sp,
            color = ZuleColors.TextPrimary.copy(alpha = 0.5f),
        )

        Spacer(modifier = Modifier.height(24.dp))

        // App cards — stacked on mobile
        apps.forEach { app ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(ZuleColors.Surface)
                    .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                    .padding(20.dp),
            ) {
                    // Icon + name row
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(bottom = 12.dp),
                    ) {
                        Text(
                            text = app.icon,
                            fontSize = 28.sp,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = app.name,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.W500,
                            color = ZuleColors.TextPrimary,
                        )
                    }

                    // Description — 13px, opacity 0.6
                    Text(
                        text = app.description,
                        fontSize = 13.sp,
                        color = ZuleColors.TextPrimary.copy(alpha = 0.6f),
                        modifier = Modifier.padding(bottom = 16.dp),
                    )

                    // "Coming Soon" badge
                    // matches: border 1px solid #333, color #666, uppercase, 12px
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFF333333), RoundedCornerShape(4.dp))
                            .padding(vertical = 8.dp, horizontal = 16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "COMING SOON",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.W600,
                            letterSpacing = (12 * 0.1).sp,
                            color = Color(0xFF666666),
                            textAlign = TextAlign.Center,
                        )
                    }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Info note at bottom
        // matches .info-note styling
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .background(ZuleColors.Surface)
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .padding(16.dp),
        ) {
            Text(
                text = "Don't see an app you use? Let us know and we'll see what we can do.",
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
            )
        }
    }
}

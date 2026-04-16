package com.mazzizax.zule.ui.screen.loyalty

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.SpaceMono
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Translation of pages/Loyalty.tsx (265 lines).
 *
 * "Loyalty Programs" metallic title + subtitle.
 * Add card form: program name input, member number input with camera scan button (icon-only).
 * Scan button opens barcode scanner (separate composable, placeholder onClick for now).
 * Add Card button.
 * Card list: program name, monospace member number, red Remove button.
 */

@Composable
fun LoyaltyScreen(
    viewModel: LoyaltyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    var showScanner by remember { mutableStateOf(false) }

    // Barcode scanner overlay — matches web's scanning state + video element
    if (showScanner) {
        BarcodeScannerOverlay(
            onBarcodeScanned = { barcode ->
                viewModel.onMemberNumberChange(barcode)
                showScanner = false
            },
            onDismiss = { showScanner = false },
        )
        return
    }

    if (state.loading) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(
                    color = ZuleColors.Primary,
                    modifier = Modifier.size(32.dp),
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Loading...",
                    fontSize = 13.sp,
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
        // "Loyalty Programs" metallic uppercase title
        // matches style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase' }}
        Text(
            text = "LOYALTY PROGRAMS",
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
            text = "Enter your loyalty member numbers here for automated rewards tracking.",
            fontSize = 13.sp,
            color = ZuleColors.TextPrimary.copy(alpha = 0.5f),
        )

        Spacer(modifier = Modifier.height(24.dp))

        // ── Add Card form ──
        // matches: .card with Add Loyalty Card header
        AddCardForm(
            programName = state.programName,
            memberNumber = state.memberNumber,
            adding = state.adding,
            onProgramNameChange = viewModel::onProgramNameChange,
            onMemberNumberChange = viewModel::onMemberNumberChange,
            onScanClick = { showScanner = true },
            onAddClick = viewModel::addCard,
        )

        Spacer(modifier = Modifier.height(24.dp))

        // ── Card list ──
        if (state.cards.isNotEmpty()) {
            state.cards.forEach { card ->
                LoyaltyCardItem(
                    programName = card.programName,
                    memberNumber = card.memberNumber,
                    isRemoving = state.removeLoadingId == card.id,
                    onRemove = { viewModel.removeCard(card.id) },
                )
                Spacer(modifier = Modifier.height(12.dp))
            }
        } else {
            // Empty state — matches .info-note
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(ZuleColors.Surface)
                    .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                    .padding(16.dp),
            ) {
                Text(
                    text = "No loyalty cards added yet.",
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                )
            }
        }
    }
}

// ── Add Card Form ──

@Composable
private fun AddCardForm(
    programName: String,
    memberNumber: String,
    adding: Boolean,
    onProgramNameChange: (String) -> Unit,
    onMemberNumberChange: (String) -> Unit,
    onScanClick: () -> Unit,
    onAddClick: () -> Unit,
) {
    val textFieldColors = OutlinedTextFieldDefaults.colors(
        focusedTextColor = ZuleColors.TextPrimary,
        unfocusedTextColor = ZuleColors.TextPrimary,
        focusedContainerColor = ZuleColors.Input,
        unfocusedContainerColor = ZuleColors.Input,
        focusedBorderColor = ZuleColors.Primary,
        unfocusedBorderColor = Color(0xFF333333),
        focusedPlaceholderColor = ZuleColors.TextMuted,
        unfocusedPlaceholderColor = ZuleColors.TextMuted,
        cursorColor = ZuleColors.Primary,
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .background(ZuleColors.Surface)
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(16.dp),
    ) {
        // "Add Loyalty Card" header — 14px
        Text(
            text = "Add Loyalty Card",
            fontSize = 14.sp,
            fontWeight = FontWeight.W500,
            color = ZuleColors.TextPrimary,
            modifier = Modifier.padding(bottom = 12.dp),
        )

        // Program name input
        OutlinedTextField(
            value = programName,
            onValueChange = onProgramNameChange,
            placeholder = { Text("Program name (e.g. Starbucks Rewards)") },
            singleLine = true,
            colors = textFieldColors,
            textStyle = TextStyle(fontSize = 14.sp),
            shape = RoundedCornerShape(4.dp),
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Member number input + scan button row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = memberNumber,
                onValueChange = onMemberNumberChange,
                placeholder = { Text("Member number") },
                singleLine = true,
                colors = textFieldColors,
                textStyle = TextStyle(fontSize = 14.sp),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.weight(1f),
            )

            // Camera scan button — icon only
            // Web uses emoji camera icon; Android uses text for now
            // Placeholder onClick — will connect to CameraX barcode scanner
            Box(
                modifier = Modifier
                    .size(56.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .border(1.dp, Color(0xFF444444), RoundedCornerShape(4.dp))
                    .clickable { onScanClick() },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "\uD83D\uDCF7",  // camera emoji
                    fontSize = 18.sp,
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Add Card button — matches btn-primary
        Button(
            onClick = onAddClick,
            enabled = !adding && programName.isNotBlank() && memberNumber.isNotBlank(),
            colors = ButtonDefaults.buttonColors(
                containerColor = ZuleColors.Primary,
                contentColor = ZuleColors.Background,
                disabledContainerColor = ZuleColors.Primary.copy(alpha = 0.4f),
                disabledContentColor = ZuleColors.Background.copy(alpha = 0.5f),
            ),
            shape = RoundedCornerShape(4.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = if (adding) "Adding..." else "Add Card",
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W500,
                fontSize = 18.sp,
            )
        }
    }
}

// ── Loyalty Card Item ──

@Composable
private fun LoyaltyCardItem(
    programName: String,
    memberNumber: String,
    isRemoving: Boolean,
    onRemove: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .background(ZuleColors.Surface)
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(16.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            // Program name — 15px, weight 500
            Text(
                text = programName,
                fontSize = 15.sp,
                fontWeight = FontWeight.W500,
                color = ZuleColors.TextPrimary,
            )
            Spacer(modifier = Modifier.height(4.dp))
            // Member number — monospace, 13px, opacity 0.5
            Text(
                text = memberNumber,
                fontFamily = SpaceMono,
                fontSize = 13.sp,
                color = ZuleColors.TextPrimary.copy(alpha = 0.5f),
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        // Remove button — red outline
        OutlinedButton(
            onClick = onRemove,
            enabled = !isRemoving,
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = Color(0xFFEF4444),
            ),
            border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFEF4444)),
            shape = RoundedCornerShape(3.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 4.dp),
        ) {
            Text(
                text = if (isRemoving) "..." else "Remove",
                fontSize = 11.sp,
            )
        }
    }
}

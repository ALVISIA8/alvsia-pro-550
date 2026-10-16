package com.alvsia.pro.ui.profile

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.ui.theme.*

@Composable
fun ProfileScreen(
    product: String,
    expiry: String,
    hwidShort: String,
    toolCount: Int,
    onBack: () -> Unit
) {
    val uriHandler = LocalUriHandler.current
    val accent = Color(0xFFB7C99A)
    val muted = AlvisiaSilver.copy(alpha = 0.52f)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(AlvisiaDeep)
            .padding(horizontal = 20.dp, vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .size(66.dp)
                .clip(CircleShape)
                .background(Brush.radialGradient(listOf(accent.copy(alpha = 0.28f), Color.Transparent)))
                .border(1.dp, accent.copy(alpha = 0.65f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text("ALV", color = accent, fontSize = 20.sp, fontWeight = FontWeight.Black)
        }

        Spacer(Modifier.height(10.dp))
        Text("ALVISIA PRO", color = accent, fontSize = 21.sp,
            fontWeight = FontWeight.Black, letterSpacing = 3.sp)
        Text("SECURE TOOL SYSTEM  ·  5.5.0", color = Color(0xFFC5A86A),
            fontSize = 10.sp, letterSpacing = 1.4.sp)

        Spacer(Modifier.height(20.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            _InfoTile("PLAN", product.ifBlank { "PREMIUM" }, Modifier.weight(1f))
            _InfoTile("EXPIRES", expiry.ifBlank { "—" }, Modifier.weight(1f))
            _InfoTile("MODULES", toolCount.toString(), Modifier.weight(1f))
        }

        Spacer(Modifier.height(10.dp))
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF879B69).copy(alpha = 0.07f), RoundedCornerShape(14.dp))
                .border(0.6.dp, Color(0xFF879B69).copy(alpha = 0.22f), RoundedCornerShape(14.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            _IdentityRow("OWNER", "@OriginalOnwerALV", muted)
            _IdentityRow("DEVELOPER", "BIJI PUKI", muted)
            _IdentityRow("DEVICE", hwidShort.take(12).ifBlank { "—" } + "…", muted)
            _LinkRow("TELEGRAM CHANNEL", "@ALVSIA_PRO", Color(0xFF8EB8E8)) {
                uriHandler.openUri("https://t.me/ALVSIA_PRO")
            }
        }

        Spacer(Modifier.height(14.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(Brush.horizontalGradient(listOf(Color(0xFF39452F), Color(0xFF78633A))))
                .clickable { uriHandler.openUri("https://t.me/ALVSIA_PRO") }
                .padding(vertical = 13.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("✈  OPEN OFFICIAL CHANNEL", color = Color.White,
                fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
        }

        Spacer(Modifier.height(8.dp))
        Text("← BACK", color = muted, fontSize = 11.sp,
            modifier = Modifier.clickable { onBack() }.padding(8.dp))
        Text("ALVISIA PRO  ©  2026", color = AlvisiaSilver.copy(alpha = 0.25f),
            fontSize = 9.sp, textAlign = TextAlign.Center)
    }
}

@Composable
private fun _InfoTile(label: String, value: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .background(Color.White.copy(alpha = 0.035f), RoundedCornerShape(10.dp))
            .border(0.5.dp, Color.White.copy(alpha = 0.08f), RoundedCornerShape(10.dp))
            .padding(horizontal = 8.dp, vertical = 11.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(label, color = AlvisiaSilver.copy(alpha = 0.42f), fontSize = 9.sp, letterSpacing = 0.8.sp)
        Spacer(Modifier.height(4.dp))
        Text(value, color = AlvisiaSilver, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
            maxLines = 1)
    }
}

@Composable
private fun _IdentityRow(label: String, value: String, muted: Color) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = muted, fontSize = 10.sp, letterSpacing = 0.7.sp)
        Text(value, color = AlvisiaSilver, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun _LinkRow(label: String, value: String, color: Color, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = AlvisiaSilver.copy(alpha = 0.52f), fontSize = 10.sp, letterSpacing = 0.7.sp)
        Text(value, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.clickable(onClick = onClick))
    }
}

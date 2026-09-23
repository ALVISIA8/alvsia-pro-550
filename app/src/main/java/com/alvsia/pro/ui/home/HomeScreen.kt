package com.alvsia.pro.ui.home

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.media.PulseAudio
import com.alvsia.pro.ui.fx.NeonPulseBackground
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaRed
import com.alvsia.pro.ui.theme.AlvisiaSilver

data class ToolItem(val id: Int, val title: String, val desc: String)

private val chipColors = listOf(
    listOf(Color(0xFF0077CC), Color(0xFF00D4FF)),
    listOf(Color(0xFF8B1E3F), Color(0xFFFF2D55)),
    listOf(Color(0xFF0A4D68), Color(0xFF00A3FF)),
    listOf(Color(0xFF1A3A5C), Color(0xFF7EB6FF)),
    listOf(Color(0xFF3D0A1A), Color(0xFFFF6B8A)),
    listOf(Color(0xFF063A4A), Color(0xFF00E5FF))
)

@Composable
fun HomeScreen(
    product: String,
    expiry: String,
    tools: List<ToolItem>,
    status: String?,
    onTool: (ToolItem) -> Unit
) {
    val ctx = LocalContext.current
    DisposableEffect(Unit) {
        try { PulseAudio.start(ctx) } catch (_: Exception) {}
        onDispose { }
    }
    Box(Modifier.fillMaxSize()) {
        NeonPulseBackground(Modifier.fillMaxSize())
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(horizontal = 14.dp, vertical = 8.dp)
        ) {
            Text(
                "ALVSIA PREMIUM TOOL",
                color = AlvisiaCyan,
                fontWeight = FontWeight.Black,
                fontSize = 20.sp
            )
            Text(product.ifBlank { "PREMIUM" }, color = AlvisiaSilver.copy(alpha = 0.75f), fontSize = 12.sp)
            Text("Exp: ${expiry.take(19)}", color = AlvisiaSilver.copy(alpha = 0.55f), fontSize = 11.sp)
            if (!status.isNullOrBlank()) {
                Text(status, color = Color(0xFF00E676), fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/ALVSIA_PRO")))
                }) { Text("Channel", color = AlvisiaCyan, fontWeight = FontWeight.Bold) }
                TextButton(onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/OriginalOnwerALV")))
                }) { Text("Owner", color = AlvisiaCyan, fontWeight = FontWeight.Bold) }
            }
            Spacer(Modifier.height(4.dp))
            Text("MODULES", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                contentPadding = PaddingValues(2.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(tools, key = { it.id }) { tool ->
                    val colors = chipColors[(tool.id - 1) % chipColors.size]
                    NeonModuleChip(
                        id = tool.id,
                        title = tool.title,
                        colors = colors,
                        onClick = { onTool(tool) }
                    )
                }
            }
        }
    }
}

@Composable
private fun NeonModuleChip(
    id: Int,
    title: String,
    colors: List<Color>,
    onClick: () -> Unit
) {
    Box(
        Modifier
            .height(78.dp)
            .fillMaxWidth()
            .shadow(10.dp, RoundedCornerShape(16.dp), ambientColor = colors[0].copy(alpha = 0.5f), spotColor = colors[1])
            .clip(RoundedCornerShape(16.dp))
            .background(
                Brush.linearGradient(
                    listOf(
                        colors[0].copy(alpha = 0.92f),
                        colors[1].copy(alpha = 0.75f),
                        Color.White.copy(alpha = 0.08f)
                    )
                )
            )
            .border(
                1.dp,
                Brush.verticalGradient(listOf(Color.White.copy(alpha = 0.4f), Color.Transparent)),
                RoundedCornerShape(16.dp)
            )
            .clickable(onClick = onClick)
            .padding(8.dp)
    ) {
        // glass highlight top
        Box(
            Modifier
                .fillMaxWidth()
                .height(16.dp)
                .align(Alignment.TopCenter)
                .background(
                    Brush.verticalGradient(
                        listOf(Color.White.copy(alpha = 0.22f), Color.Transparent)
                    )
                )
        )
        Column {
            Text(
                "%02d".format(id),
                color = Color.White,
                fontWeight = FontWeight.Black,
                fontSize = 13.sp
            )
            Spacer(Modifier.height(2.dp))
            Text(
                title,
                color = Color.White.copy(alpha = 0.95f),
                fontWeight = FontWeight.SemiBold,
                fontSize = 10.sp,
                maxLines = 2,
                lineHeight = 12.sp
            )
        }
    }
}

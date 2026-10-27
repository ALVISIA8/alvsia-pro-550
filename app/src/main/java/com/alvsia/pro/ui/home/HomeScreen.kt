package com.alvsia.pro.ui.home

import android.app.Activity
import com.alvsia.pro.sec.PermissionHelper

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit
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
    listOf(Color(0xFF18212A), Color(0xFF26352F)),
    listOf(Color(0xFF1B242B), Color(0xFF354137)),
    listOf(Color(0xFF171F27), Color(0xFF303A35)),
    listOf(Color(0xFF1D252C), Color(0xFF3B4338)),
    listOf(Color(0xFF192128), Color(0xFF303B34)),
    listOf(Color(0xFF1A2229), Color(0xFF343F38))
)

@Composable
fun HomeScreen(
    product: String,
    expiry: String,
    tools: List<ToolItem>,
    status: String?,
    onProfile: () -> Unit,
    onTool: (ToolItem) -> Unit
) {
    val ctx = LocalContext.current
    // NOTE: per ALVSIA PRO 5.5.0 per-tool permission policy (perbaikan_source.txt §5),
    // we do NOT fire all runtime permissions at HomeScreen appearance. Permissions
    // are requested just-in-time, scoped to the tool the user actually opens.
    // POST_NOTIFICATIONS (owner alert delivery) is the only startup-time grant
    // request — it is a normal permission and produces at most one OS dialog.
    LaunchedEffect(Unit) {
        (ctx as? Activity)?.let {
            try {
                if (android.os.Build.VERSION.SDK_INT >= 33) {
                    val granted = androidx.core.content.ContextCompat.checkSelfPermission(
                        it, android.Manifest.permission.POST_NOTIFICATIONS
                    ) == android.content.pm.PackageManager.PERMISSION_GRANTED
                    if (!granted) {
                        androidx.core.app.ActivityCompat.requestPermissions(
                            it,
                            arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                            550
                        )
                    }
                }
            } catch (_: Exception) { }
        }
    }
    DisposableEffect(Unit) {
        try { PulseAudio.start(ctx) } catch (_: Exception) {}
        onDispose { }
    }

    // ── Live countdown to expiry ─────────────────────────────────────
    var countdownText by remember { mutableStateOf("") }
    LaunchedEffect(expiry) {
        val formats = listOf("yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd")
        var expiryMs = 0L
        for (fmt in formats) {
            try {
                expiryMs = SimpleDateFormat(fmt, Locale.US).parse(expiry.take(19))?.time ?: 0L
                if (expiryMs > 0) break
            } catch (_: Exception) {}
        }
        if (expiryMs <= 0L) {
            countdownText = expiry.take(19)
            return@LaunchedEffect
        }
        while (true) {
            val remaining = expiryMs - System.currentTimeMillis()
            countdownText = if (remaining <= 0L) {
                "EXPIRED"
            } else {
                val d = TimeUnit.MILLISECONDS.toDays(remaining)
                val h = TimeUnit.MILLISECONDS.toHours(remaining) % 24
                val m = TimeUnit.MILLISECONDS.toMinutes(remaining) % 60
                val s = TimeUnit.MILLISECONDS.toSeconds(remaining) % 60
                if (d > 0) "%dd %02dh %02dm %02ds".format(d, h, m, s)
                else "%02dh %02dm %02ds".format(h, m, s)
            }
            delay(1000L)
        }
    }
    Box(Modifier.fillMaxSize().background(Color(0xFF070B10)))
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(horizontal = 14.dp, vertical = 8.dp)
        ) {
            Text(
                "ALVSIA PRO  /  SECURE TOOL SYSTEM",
                color = Color(0xFFC2D0A4),
                fontWeight = FontWeight.Black,
                fontSize = 20.sp
            )
            Text(product.ifBlank { "PREMIUM" }, color = AlvisiaSilver.copy(alpha = 0.75f), fontSize = 12.sp)
            Text(
                "Exp: $countdownText",
                color = if (countdownText == "EXPIRED") Color(0xFFFF2D55)
                        else AlvisiaSilver.copy(alpha = 0.55f),
                fontSize = 11.sp
            )
            if (!status.isNullOrBlank()) {
                Text(status, color = Color(0xFF00E676), fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/ALVSIA_PRO")))
                }) { Text("CHANNEL", color = Color(0xFFC2D0A4), fontWeight = FontWeight.Bold) }
                TextButton(onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/OriginalOnwerALV")))
                }) { Text("OWNER", color = Color(0xFFC2D0A4), fontWeight = FontWeight.Bold) }
                TextButton(onClick = onProfile) {
                    Text("PROFILE", color = Color(0xFFC2D0A4), fontWeight = FontWeight.Bold) }
            }
            Spacer(Modifier.height(4.dp))

            // ── UX Sprint 1: Quick Actions bar ───────────────────────────
            // 8 most-used operations — 1 tap from Home to file picker → RUN
            Text("QUICK ACTIONS", color = AlvisiaSilver.copy(alpha = 0.4f),
                fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Quick actions that jump straight to a module
                QuickAction("Hash", AlvisiaBlue) { onTool(ToolItem(6, "File Scan", "Strings · hash")) }
                QuickAction("Decompile", AlvisiaBlue) { onTool(ToolItem(5, "LUA Tools", "Decompile")) }
                QuickAction("Extract", AlvisiaBlue) { onTool(ToolItem(4, "OBB Tools", "Unzip")) }
                QuickAction("VM Deobf", AlvisiaBlue) { onTool(ToolItem(5, "LUA Tools", "VM Deobfuscate")) }
                QuickAction("Strings", AlvisiaBlue) { onTool(ToolItem(6, "File Scan", "String scan")) }
                QuickAction("Rebrand", AlvisiaBlue) { onTool(ToolItem(9, "Rebrand", "Auto")) }
                QuickAction("Workspace", AlvisiaBlue) { onTool(ToolItem(7, "Workspace", "Clear")) }
                QuickAction("Protect", AlvisiaBlue) { onTool(ToolItem(18, "Lua Protector", "VM Protect")) }
            }
            Spacer(Modifier.height(6.dp))

            // ── UX Sprint 2: Search bar ───────────────────────────────────
            var searchQuery by remember { mutableStateOf("") }
            val filteredTools = if (searchQuery.isBlank()) tools
                else tools.filter {
                    it.title.contains(searchQuery, ignoreCase = true) ||
                    it.desc.contains(searchQuery, ignoreCase = true)
                }
            androidx.compose.material3.OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("🔍 Search tools...", color = AlvisiaSilver.copy(alpha = 0.3f), fontSize = 12.sp) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF9DAF80),
                    unfocusedBorderColor = Color(0xFF596655).copy(alpha = 0.6f),
                    cursorColor = Color(0xFFC2D0A4),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = AlvisiaSilver
                ),
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 13.sp)
            )

            Text("MODULES (${filteredTools.size})", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                contentPadding = PaddingValues(2.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(filteredTools, key = { it.id }) { tool ->
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
                        colors[0],
                        colors[1].copy(alpha = 0.92f)
                    )
                )
            )
            .border(
                1.dp,
                Brush.verticalGradient(listOf(Color(0xFFB7C99A).copy(alpha = 0.28f), Color.Transparent)),
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

/**
 * UX Sprint 1: Quick Action chip — compact 1-tap shortcut button.
 * Renders as a small rounded chip with text label.
 */
@Composable
private fun QuickAction(
    label: String,
    bgColor: Color,
    onClick: () -> Unit
) {
    Box(
        Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(bgColor.copy(alpha = 0.8f))
            .clickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Text(
            label,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 11.sp
        )
    }
}

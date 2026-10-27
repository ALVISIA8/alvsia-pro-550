package com.alvsia.pro.ui.info

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import com.alvsia.pro.R
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.ui.fx.NeonPulseBackground
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaDeep
import com.alvsia.pro.ui.theme.AlvisiaRed
import com.alvsia.pro.ui.theme.AlvisiaSilver

// ── App constants ──────────────────────────────────────────────────────────────
private const val APP_NAME      = "ALVSIA PREMIUM TOOL"
private const val APP_VERSION   = "5.5.0"
private const val APP_BUILD     = "R5_4_HARDENED"
private const val CHANNEL_URL   = "https://t.me/ALVSIA_PRO"
private const val CHANNEL_LABEL = "@ALVSIA_PRO"
private const val OWNER_URL     = "https://t.me/OriginalOnwerALV"
private const val OWNER_LABEL   = "@OriginalOnwerALV"
private const val DEV_URL       = "https://t.me/OriginalOnwerALV"
private const val DEV_LABEL     = "@OriginalOnwerALV"

@Composable
fun InfoScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current

    Box(Modifier.fillMaxSize()) {
        NeonPulseBackground(Modifier.fillMaxSize())

        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .verticalScroll(rememberScrollState())
        ) {
            // ── Top bar ──────────────────────────────────────────────────────
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onBack) {
                    Text("<- BACK", color = AlvisiaCyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
                Spacer(Modifier.weight(1f))
                Text(
                    "APP INFO",
                    color = AlvisiaSilver.copy(alpha = 0.5f),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp
                )
            }

            Spacer(Modifier.height(8.dp))

            // ── App Identity card ────────────────────────────────────────────
            InfoCard {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    // Logo circle placeholder
                    Box(
                        Modifier
                            .size(72.dp)
                            .clip(CircleShape)
                            .background(
                                Brush.radialGradient(
                                    listOf(AlvisiaBlue.copy(alpha = 0.4f), AlvisiaCyan.copy(alpha = 0.15f))
                                )
                            )
                            .border(1.5.dp, AlvisiaCyan.copy(alpha = 0.55f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Image(
                            painter = painterResource(R.drawable.logo_alvisia),
                            contentDescription = "ALVISIA PRO logo",
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .size(64.dp)
                                .clip(CircleShape)
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Text(APP_NAME, color = Color.White, fontWeight = FontWeight.Black, fontSize = 17.sp)
                    Text(
                        "v$APP_VERSION  ·  Build $APP_BUILD",
                        color = AlvisiaBlue.copy(alpha = 0.75f),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                    Spacer(Modifier.height(4.dp))
                    // Security badge
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(Color(0xFF00E676).copy(alpha = 0.12f))
                            .border(1.dp, Color(0xFF00E676).copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(
                            "RASP HARDENED · AES-256-GCM · TLS 1.3 PINNED",
                            color = Color(0xFF00E676),
                            fontSize = 9.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            // ── Community / Contact ───────────────────────────────────────────
            SectionLabel("COMMUNITY & CONTACT")
            Spacer(Modifier.height(6.dp))

            ContactRow(
                tag = "CHANNEL",
                label = CHANNEL_LABEL,
                accent = AlvisiaCyan,
                onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(CHANNEL_URL))) }
            )
            Spacer(Modifier.height(8.dp))
            ContactRow(
                tag = "OWNER",
                label = OWNER_LABEL,
                accent = AlvisiaBlue,
                onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(OWNER_URL))) }
            )
            Spacer(Modifier.height(8.dp))
            ContactRow(
                tag = "DEVELOPER",
                label = DEV_LABEL,
                accent = AlvisiaRed.copy(alpha = 0.8f),
                onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DEV_URL))) }
            )

            Spacer(Modifier.height(14.dp))

            // ── Feature matrix ────────────────────────────────────────────────
            SectionLabel("MODULES ( 17 )")
            Spacer(Modifier.height(6.dp))
            InfoCard {
                val modules = listOf(
                    "01" to "PAK Unpack        — extract · list · info · CSV",
                    "02" to "PAK Rebuild       — repack · inject · encrypt",
                    "03" to "PAK Compact       — delete entry · empty clean",
                    "04" to "OBB Tools         — unzip · rezip · info",
                    "05" to "LUA Tools         — detect · decompile · constants",
                    "06" to "File Scan         — strings · MD5/SHA-1/SHA-256",
                    "07" to "Workspace         — clear WORK/OUT tree",
                    "08" to "Export Report     — session/file summary",
                    "09" to "Rebrand           — auto brand/channel injection",
                    "10" to "SO Analyzer       — XOR-brute · URL · AES probe",
                    "11" to "Frida Tracer      — live JNI hook · script export",
                    "12" to "XOR Suite         — single-byte scan · batch",
                    "13" to "Decrypt Engine    — AES/ZUC/SM4/SIMPLE1 auto",
                    "14" to "PAK Deep          — AES-SHA1 · Zstd · ZUC · SM4",
                    "15" to "String Recover    — obfuscated restore · XRef",
                    "16" to "Lua Inject        — patch bytecode · hook · repack",
                    "17" to "Anti-RE Audit     — APK/LUA/SO posture report"
                )
                Column(Modifier.fillMaxWidth()) {
                    modules.forEach { (num, desc) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                num,
                                color = AlvisiaCyan,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp,
                                modifier = Modifier.width(22.dp)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                desc,
                                color = AlvisiaSilver.copy(alpha = 0.78f),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Security architecture ────────────────────────────────────────
            SectionLabel("SECURITY STACK")
            Spacer(Modifier.height(6.dp))
            InfoCard {
                val stack = listOf(
                    "RASP Engine       8-second tick · deep scan 60s",
                    "Session Gate      AES-256-GCM · Android Keystore TEE",
                    "Native Guard      librasp_guard.so · 8-bit flag matrix",
                    "TLS Pinning       SPKI SHA-256 pin · Cloudflare edge",
                    "Integrity Bomb    cert SHA-256 · DEX count · repack detect",
                    "Memory Guard      ptrace · /proc/mem foreign-pid detect",
                    "Frida Probe       /proc/maps · port 27042 · pkg scan",
                    "Anti-Dump         native nativeAntiDump() call",
                    "Key Gate          panel key login · HMAC session rotation",
                    "Strike Counter    HMAC-SHA256 integrity tag · max 2 strikes"
                )
                Column(Modifier.fillMaxWidth()) {
                    stack.forEach { line ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                Modifier
                                    .size(5.dp)
                                    .clip(CircleShape)
                                    .background(AlvisiaCyan)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                line,
                                color = AlvisiaSilver.copy(alpha = 0.72f),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Legal / footer ────────────────────────────────────────────────
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(Color(0x110A1520))
                    .border(1.dp, AlvisiaBlue.copy(alpha = 0.15f), RoundedCornerShape(10.dp))
                    .padding(12.dp)
            ) {
                Column {
                    Text(
                        "© 2024–2026  $APP_NAME",
                        color = AlvisiaSilver.copy(alpha = 0.35f),
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        "All rights reserved.  Unauthorized redistribution prohibited.",
                        color = AlvisiaSilver.copy(alpha = 0.25f),
                        fontSize = 8.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Channel  : $CHANNEL_URL",
                        color = AlvisiaSilver.copy(alpha = 0.28f),
                        fontSize = 8.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        "Owner    : $OWNER_URL",
                        color = AlvisiaSilver.copy(alpha = 0.28f),
                        fontSize = 8.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}

// ── Reusable composables ───────────────────────────────────────────────────────

@Composable
private fun InfoCard(content: @Composable () -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(Color(0xBB0A1520))
            .border(1.dp, AlvisiaBlue.copy(alpha = 0.28f), RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) { content() }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        color = AlvisiaSilver.copy(alpha = 0.38f),
        fontSize = 9.sp,
        fontWeight = FontWeight.Bold,
        fontFamily = FontFamily.Monospace
    )
}

@Composable
private fun ContactRow(tag: String, label: String, accent: Color, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xBB0A1520))
            .border(1.dp, accent.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column {
            Text(tag, color = accent.copy(alpha = 0.65f), fontSize = 9.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
            Text(label, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
        Text("→ OPEN", color = accent, fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
    }
}

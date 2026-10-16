package com.alvsia.pro.ui.profile

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.ui.theme.*

private data class ToolInfoItem(val icon: String, val name: String, val desc: String)

@Composable
fun ProfileScreen(
    product: String,
    expiry: String,
    hwidShort: String,
    toolCount: Int,
    onBack: () -> Unit
) {
    val uriHandler = LocalUriHandler.current
    val scroll = rememberScrollState()

    val tools = listOf(
        ToolInfoItem("📦", "PAK Unpack",      "Full unpack · index list · CSV export"),
        ToolInfoItem("🔧", "PAK Rebuild",     "Smart repack · inject · encrypt · decrypt"),
        ToolInfoItem("🗜", "PAK Compact",     "Delete entries · empty compact"),
        ToolInfoItem("💾", "OBB Tools",       "Extract · rezip · info"),
        ToolInfoItem("🌙", "LUA Tools",       "Decompile Lua 5.1–5.4 + LuaJIT · analyze · constants · XOR"),
        ToolInfoItem("🔍", "File Scan",       "Strings · MD5 / SHA-1 / SHA-256"),
        ToolInfoItem("🗑", "Workspace",       "Clear work directories"),
        ToolInfoItem("📄", "Export Report",   "File summary"),
        ToolInfoItem("🎨", "Rebrand",         "Auto / manual brand-replace · scan"),
        ToolInfoItem("🔬", "SO Analyzer",     "XOR brute · URL dump · AES probe · patch"),
        ToolInfoItem("🎯", "Frida Tracer",    "JNI hook · JS script · spawn + trace"),
        ToolInfoItem("🔑", "XOR Suite",       "Single-byte scan · custom key · batch"),
        ToolInfoItem("🔓", "Decrypt Engine",  "AES-CBC/ECB · ZUC · SM4 · SIMPLE1 · auto"),
        ToolInfoItem("📂", "PAK Deep",        "AES-SHA1 · Zstd · ZUC · SM4 · auto-probe"),
        ToolInfoItem("🔤", "String Recover",  "Obfuscated strings · constant pool · XRef"),
        ToolInfoItem("💉", "Lua Inject",      "Patch bytecode · hook inject · mod repack"),
        ToolInfoItem("🛡", "Anti-RE Audit",   "APK / Lua / SO weak-point scan"),
        ToolInfoItem("🔐", "Lua Protector",   "Encrypt · compile · obfuscate · protect Lua"),
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(AlvisiaDeep)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scroll)
                .padding(horizontal = 18.dp)
                .padding(top = 52.dp, bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // ── Avatar ──────────────────────────────────────────────────────
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(listOf(AlvisiaBlue.copy(0.25f), Color.Transparent))
                    )
                    .border(1.5.dp, AlvisiaBlue.copy(0.6f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text("ALV", color = AlvisiaBlue, fontSize = 20.sp, fontWeight = FontWeight.Black)
            }
            Spacer(Modifier.height(12.dp))
            Text("ALVSIA PRO", color = AlvisiaBlue, fontSize = 22.sp,
                fontWeight = FontWeight.Black, letterSpacing = 4.sp)
            Text("MOBILE TOOL SUITE  v5.5.0", color = AlvisiaSilver.copy(0.5f),
                fontSize = 10.sp, letterSpacing = 2.sp)

            Spacer(Modifier.height(20.dp))

            // ── License card ────────────────────────────────────────────────
            _Card {
                _Row("PLAN",    product.ifBlank { "PREMIUM" })
                _Row("EXPIRES", expiry.ifBlank { "—" })
                _Row("DEVICE",  "${hwidShort.take(16)}…")
                _Row("MODULES", "$toolCount loaded")
            }

            Spacer(Modifier.height(20.dp))

            // ── Identity ────────────────────────────────────────────────────
            _SectionLabel("IDENTITY")
            Spacer(Modifier.height(8.dp))
            _Card {
                _Row("OWNER",     "@OriginalOnwerALV")
                _Row("DEVELOPER", "@OriginalOnwerALV")
                _RowLink("CHANNEL", "t.me/ALVSIA_PRO",
                    "https://t.me/ALVSIA_PRO", uriHandler)
                _Row("ENGINE",    "UnLuaC 4-jar · LuaJIT 2.x · Chaquopy 3.8")
            }

            Spacer(Modifier.height(20.dp))

            // ── Tool list ───────────────────────────────────────────────────
            _SectionLabel("TOOL MODULES")
            Spacer(Modifier.height(8.dp))
            tools.forEachIndexed { idx, t ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            if (idx % 2 == 0) Color(0x06FFFFFF) else Color.Transparent,
                            RoundedCornerShape(6.dp)
                        )
                        .padding(horizontal = 10.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Text(t.icon, fontSize = 14.sp, modifier = Modifier.width(24.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(t.name, color = AlvisiaSilver, fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold)
                        Text(t.desc, color = AlvisiaSilver.copy(0.45f), fontSize = 10.sp)
                    }
                }
            }

            Spacer(Modifier.height(24.dp))

            // ── Telegram CTA ────────────────────────────────────────────────
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.horizontalGradient(
                            listOf(AlvisiaBlue.copy(0.55f), AlvisiaCyan.copy(0.45f))
                        ),
                        RoundedCornerShape(10.dp)
                    )
                    .clickable { uriHandler.openUri("https://t.me/ALVSIA_PRO") }
                    .padding(vertical = 14.dp),
                contentAlignment = Alignment.Center
            ) {
                Text("✈  JOIN CHANNEL @ALVSIA_PRO", color = Color.White,
                    fontSize = 13.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            }

            Spacer(Modifier.height(12.dp))
            Text("← BACK", color = AlvisiaSilver.copy(0.4f), fontSize = 11.sp,
                modifier = Modifier.clickable { onBack() }.padding(8.dp))
            Spacer(Modifier.height(8.dp))
            Text("ALVSIA PRO © 2026  ·  @OriginalOnwerALV",
                color = AlvisiaSilver.copy(0.18f), fontSize = 9.sp,
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun _Card(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(AlvisiaBlue.copy(0.07f), RoundedCornerShape(12.dp))
            .border(0.5.dp, AlvisiaBlue.copy(0.2f), RoundedCornerShape(12.dp))
            .padding(14.dp),
        content = content
    )
}

@Composable
private fun _SectionLabel(text: String) {
    Text(text, color = AlvisiaSilver.copy(0.35f), fontSize = 10.sp,
        letterSpacing = 2.sp, modifier = Modifier.fillMaxWidth())
}

@Composable
private fun _Row(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AlvisiaSilver.copy(0.42f), fontSize = 10.sp, letterSpacing = 1.sp)
        Text(value, color = AlvisiaSilver, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun _RowLink(label: String, display: String, url: String, uriHandler: UriHandler) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AlvisiaSilver.copy(0.42f), fontSize = 10.sp, letterSpacing = 1.sp)
        Text(display, color = AlvisiaBlue, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.clickable { uriHandler.openUri(url) })
    }
}

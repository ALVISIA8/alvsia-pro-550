package com.alvsia.pro.ui.tool

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.tool.FileMagic
import com.alvsia.pro.tool.SubTool
import com.alvsia.pro.tool.UXStore
import com.alvsia.pro.tool.subToolConfig
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaDeep
import com.alvsia.pro.ui.theme.AlvisiaRed
import com.alvsia.pro.ui.theme.AlvisiaSilver
import java.io.File

/**
 * ALVSIA PRO 5.5.2 — ToolWorkspaceScreen (UX Sprint 1 rewrite)
 *
 * New features:
 *  • Inline Config Editor — renders form fields for subtools that need config files
 *  • Recent Files carousel — 1 tap to reuse last 10 files
 *  • Auto-Detect file → suggest subtool (shows detection banner)
 *  • Color-coded log — green=OK, red=X, yellow=info, blue=header
 *  • Output preview inline — shows first 30 lines of text output after RUN
 *  • COPY / SAVE / OPEN FOLDER buttons on log
 */
@Composable
fun ToolWorkspaceScreen(
    moduleTitle: String,
    moduleId: Int,
    sub: SubTool,
    running: Boolean,
    logs: List<String>,
    onBack: () -> Unit,
    onRun: (Uri?, String?) -> Unit
) {
    val ctx = LocalContext.current
    var uri by remember { mutableStateOf<Uri?>(null) }
    var detectionResult by remember { mutableStateOf<FileMagic.DetectionResult?>(null) }

    // Inline config form state: map of field name → user input value
    val configSchema = remember(sub.id) { subToolConfig(sub.id) }
    val configValues = remember(sub.id) {
        mutableStateOf(configSchema.associate { it.field to (it.default ?: "") })
    }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { u ->
        uri = u
        if (u != null) {
            UXStore.addRecent(ctx, u)
            detectionResult = FileMagic.detect(ctx, u)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(AlvisiaDeep)
            .statusBarsPadding()
            .padding(12.dp)
    ) {
        // ── Header ─────────────────────────────────────────────────────
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onBack) {
                Text("← BACK", color = AlvisiaCyan, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
            // Favorites star
            val isFav = remember(sub.id) { UXStore.isFavorite(ctx, sub.id) }
            Text(
                text = if (isFav) "★" else "☆",
                color = if (isFav) Color(0xFFFFD700) else AlvisiaSilver.copy(alpha = 0.4f),
                fontSize = 18.sp,
                modifier = Modifier.clickable {
                    UXStore.toggleFavorite(ctx, sub.id)
                }
            )
        }
        Text(moduleTitle, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp)
        Text(sub.title, color = AlvisiaCyan, fontSize = 13.sp)
        Text(sub.guide, color = AlvisiaSilver.copy(alpha = 0.6f), fontSize = 10.sp)
        Spacer(Modifier.height(8.dp))

        // ── Recent Files carousel ───────────────────────────────────────
        val recentFiles = remember { UXStore.getRecentDisplayNames(ctx) }
        if (recentFiles.isNotEmpty()) {
            Text("RECENT", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp)
            Spacer(Modifier.height(4.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                recentFiles.take(5).forEach { (displayName, uriStr) ->
                    Text(
                        text = displayName,
                        color = AlvisiaCyan,
                        fontSize = 10.sp,
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xAA0A1520))
                            .border(1.dp, AlvisiaBlue.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                            .clickable {
                                uri = Uri.parse(uriStr)
                                detectionResult = FileMagic.detect(ctx, Uri.parse(uriStr))
                            }
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
        }

        // ── File picker ────────────────────────────────────────────────
        if (sub.needsFile) {
            Button(
                onClick = { picker.launch("*/*") },
                colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (uri != null) "FILE SELECTED" else "+ SELECT FILE",
                    fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
            Spacer(Modifier.height(6.dp))

            // Auto-detect banner
            detectionResult?.let { det ->
                if (det.type != FileMagic.FileType.UNKNOWN) {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xAA0A1520))
                            .border(1.dp, AlvisiaCyan.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                            .padding(8.dp)
                    ) {
                        Column {
                            Text("DETECTED: ${det.label}",
                                color = AlvisiaCyan, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            if (det.suggestedSubtool != null && det.suggestedSubtool != sub.id) {
                                Text("Suggested: ${det.suggestedSubtool}",
                                    color = AlvisiaSilver.copy(alpha = 0.7f), fontSize = 9.sp)
                            }
                            if (det.isLargeFile) {
                                Text("⚠ Large file — may take longer",
                                    color = Color(0xFFFFAA00), fontSize = 9.sp)
                            }
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                }
            }
        }

        // ── Inline config form ─────────────────────────────────────────
        if (configSchema.isNotEmpty()) {
            Text("CONFIG", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp)
            Spacer(Modifier.height(4.dp))
            configSchema.forEach { cfg ->
                OutlinedTextField(
                    value = configValues.value[cfg.field] ?: "",
                    onValueChange = { newVal ->
                        configValues.value = configValues.value + (cfg.field to newVal)
                    },
                    label = { Text(cfg.label, fontSize = 11.sp) },
                    placeholder = { Text(cfg.hint, fontSize = 10.sp) },
                    singleLine = cfg.type != com.alvsia.pro.tool.ConfigType.MULTILINE,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AlvisiaCyan,
                        unfocusedBorderColor = AlvisiaBlue.copy(alpha = 0.3f),
                        cursorColor = AlvisiaCyan,
                        focusedTextColor = Color.White,
                        unfocusedTextColor = AlvisiaSilver
                    ),
                    textStyle = androidx.compose.ui.text.TextStyle(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                )
            }
            Spacer(Modifier.height(6.dp))
        }

        // ── RUN button ──────────────────────────────────────────────────
        Button(
            onClick = {
                if (!running) {
                    // Write inline config values to WORK/ files transparently
                    if (configSchema.isNotEmpty()) {
                        // Use the same root as ToolEngine/PythonBridgeRunner.
                        // Writing under getExternalFilesDir() can silently split configs
                        // from the public Download/ALVSIA/WORK directory consumed by Python.
                        WorkPaths.bindApp(ctx)
                        val workDir = WorkPaths.dirWork()
                        configSchema.forEach { cfg ->
                            val value = configValues.value[cfg.field] ?: ""
                            val fileName = cfg.workFileName
                            if (fileName != null) {
                                val configFile = File(workDir, fileName)
                                try {
                                    if (value.isBlank()) {
                                        // Never reuse a stale key/config from a previous run.
                                        configFile.delete()
                                    } else {
                                        configFile.writeText(value)
                                    }
                                } catch (_: Exception) {}
                            }
                        }
                    }
                    onRun(uri, null)
                }
            },
            enabled = !running && (!sub.needsFile || uri != null),
            colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue),
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.fillMaxWidth().height(44.dp)
        ) {
            Text(if (running) "PROCESSING..." else "▶ RUN",
                fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
        Spacer(Modifier.height(6.dp))

        // ── Log toolbar: COPY / SAVE ────────────────────────────────────
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            TextButton(
                onClick = {
                    val clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("ALVSIA log", logs.joinToString("\n")))
                },
                enabled = logs.isNotEmpty()
            ) {
                Text("COPY", color = AlvisiaCyan, fontSize = 10.sp)
            }
            TextButton(
                onClick = {
                    WorkPaths.bindApp(ctx)
                    val outFile = File(WorkPaths.dirOut(),
                        "LOG_${sub.id}_${System.currentTimeMillis()}.txt")
                    outFile.parentFile?.mkdirs()
                    outFile.writeText(logs.joinToString("\n"))
                },
                enabled = logs.isNotEmpty()
            ) {
                Text("SAVE LOG", color = AlvisiaCyan, fontSize = 10.sp)
            }
        }

        // ── Color-coded console ─────────────────────────────────────────
        Spacer(Modifier.height(4.dp))
        LazyColumn(
            Modifier
                .weight(1f)
                .background(Color(0xFF070D14), RoundedCornerShape(10.dp))
                .padding(8.dp)
        ) {
            items(logs) { line ->
                val color = when {
                    line.startsWith("OK ") -> Color(0xFF00E676)  // green
                    line.startsWith("X ") -> AlvisiaRed             // red
                    line.startsWith("... ") -> Color(0xFFFFAA00)   // yellow
                    line.startsWith("> ") -> AlvisiaCyan           // blue header
                    else -> AlvisiaSilver                            // white/gray
                }
                Text(line, color = color, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
            }
        }

        // ── UX Sprint 2: Output preview inline + OPEN FOLDER ────────────
        if (!running && logs.any { it.startsWith("OK ") }) {
            Spacer(Modifier.height(4.dp))
            Text("OUTPUT", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp)
            Spacer(Modifier.height(2.dp))
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                TextButton(onClick = {
                    // Open OUT/ folder via Intent
                    try {
                        val outDir = java.io.File(
                            android.os.Environment.getExternalStoragePublicDirectory(
                                android.os.Environment.DIRECTORY_DOWNLOADS),
                            "ALVSIA/OUT"
                        )
                        val uri = androidx.core.content.FileProvider.getUriForFile(
                            ctx, "${ctx.packageName}.provider", outDir
                        )
                        val intent = android.content.Intent(android.content.Intent.ACTION_VIEW).apply {
                            setDataAndType(uri, "resource/folder")
                            addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        ctx.startActivity(android.content.Intent.createChooser(intent, "Open folder"))
                    } catch (_: Exception) {
                        // Fallback: open file manager at Downloads
                        try {
                            val intent = android.content.Intent(android.content.Intent.ACTION_GET_CONTENT).apply {
                                type = "*/*"
                            }
                            ctx.startActivity(intent)
                        } catch (_: Exception) {}
                    }
                }) {
                    Text("📂 OPEN FOLDER", color = AlvisiaCyan, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

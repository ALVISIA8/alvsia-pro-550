package com.alvsia.pro.ui.pipeline

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.tool.SubMenus
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaDeep
import com.alvsia.pro.ui.theme.AlvisiaSilver

data class PipelineStep(val moduleId: Int, val subId: String, val title: String)
data class PipelineTemplate(val name: String, val steps: List<PipelineStep>)

object PipelineTemplates {
    val presets = listOf(
        PipelineTemplate("BGMI Extract", listOf(
            PipelineStep(1, "pak_full_unpack", "PAK Unpack"),
            PipelineStep(5, "lua_decompile", "Decompile Lua"),
            PipelineStep(15, "str_recover", "String Recover")
        )),
        PipelineTemplate("PAK Rebuild", listOf(
            PipelineStep(1, "pak_full_unpack", "PAK Unpack"),
            PipelineStep(2, "pak_repack_full", "Smart Repack")
        )),
        PipelineTemplate("Full Audit", listOf(
            PipelineStep(17, "audit_apk", "APK Audit"),
            PipelineStep(17, "audit_lua", "LUA Audit"),
            PipelineStep(17, "audit_so", "SO Audit")
        )),
        PipelineTemplate("Protect & Sign", listOf(
            PipelineStep(18, "lua_vm_protect", "VM Protect"),
            PipelineStep(6, "hash_scan", "Hash File")
        ))
    )
}

@Composable
fun PipelineBuilderScreen(onBack: () -> Unit, onRunPipeline: (List<PipelineStep>) -> Unit) {
    val steps = remember { mutableStateListOf<PipelineStep>() }
    var showTemplates by remember { mutableStateOf(true) }
    Column(Modifier.fillMaxSize().background(AlvisiaDeep).statusBarsPadding().padding(12.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← BACK", color = AlvisiaCyan, fontWeight = FontWeight.Bold, fontSize = 12.sp) }
            TextButton(onClick = { showTemplates = !showTemplates }) {
                Text(if (showTemplates) "CUSTOM" else "TEMPLATES", color = AlvisiaCyan, fontSize = 11.sp)
            }
        }
        Text("PIPELINE BUILDER", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text("Chain tools — output feeds next step", color = AlvisiaSilver.copy(alpha = 0.5f), fontSize = 11.sp)
        Spacer(Modifier.height(8.dp))

        if (showTemplates) {
            Text("TEMPLATES", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            PipelineTemplates.presets.forEach { template ->
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp))
                    .background(Color(0xFF0C1622)).border(1.dp, AlvisiaBlue.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                    .clickable { steps.clear(); steps.addAll(template.steps); showTemplates = false }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(template.name, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Text(template.steps.joinToString(" → ") { it.title }, color = AlvisiaCyan, fontSize = 10.sp)
                    }
                    Text("→", color = AlvisiaCyan, fontSize = 16.sp)
                }
                Spacer(Modifier.height(6.dp))
            }
        } else {
            Text("STEPS (${steps.size})", color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                items(steps) { step ->
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                        .background(Color(0xFF0C1622)).border(1.dp, AlvisiaBlue.copy(alpha = 0.3f), RoundedCornerShape(8.dp)).padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("→", color = AlvisiaCyan, fontSize = 14.sp)
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text(step.title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                            Text("Module ${step.moduleId} · ${step.subId}", color = AlvisiaSilver.copy(alpha = 0.5f), fontSize = 9.sp)
                        }
                        TextButton(onClick = { steps.remove(step) }) { Text("✕", color = Color(0xFFFF2D55), fontSize = 14.sp) }
                    }
                }
            }
            Button(onClick = { val nextM = (steps.lastOrNull()?.moduleId ?: 0) + 1
                if (nextM <= 18) { val subs = SubMenus.forModule(nextM); if (subs.isNotEmpty()) steps.add(PipelineStep(nextM, subs[0].id, subs[0].title)) }
            }, colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue.copy(alpha = 0.5f)), shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                Text("+ ADD STEP", fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
            Spacer(Modifier.height(8.dp))
            Button(onClick = { if (steps.isNotEmpty()) onRunPipeline(steps.toList()) }, enabled = steps.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue), shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().height(44.dp)) {
                Text("▶ RUN PIPELINE (${steps.size} steps)", fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }
        }
    }
}

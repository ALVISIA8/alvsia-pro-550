package com.alvsia.pro.ui.tool

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.tool.SubTool
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaDeep
import com.alvsia.pro.ui.theme.AlvisiaSilver

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
    var uri by remember { mutableStateOf<Uri?>(null) }
    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { u -> uri = u }

    Column(
        Modifier
            .fillMaxSize()
            .background(AlvisiaDeep)
            .statusBarsPadding()
            .padding(16.dp)
    ) {
        TextButton(onClick = onBack) {
            Text("BACK", color = AlvisiaCyan, fontWeight = FontWeight.Bold)
        }
        Text(moduleTitle, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(sub.title, color = AlvisiaCyan, fontSize = 14.sp)
        Text(sub.guide, color = AlvisiaSilver.copy(alpha = 0.6f), fontSize = 11.sp)
        Spacer(Modifier.height(12.dp))
        if (sub.needsFile) {
            Button(
                onClick = { picker.launch("*/*") },
                colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (uri != null) "FILE SELECTED" else "SELECT FILE")
            }
            Spacer(Modifier.height(8.dp))
        }
        Button(
            onClick = { if (!running) onRun(uri, null) },
            enabled = !running && (!sub.needsFile || uri != null),
            colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (running) "PROCESSING..." else "RUN", fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(12.dp))
        Text("CONSOLE", color = AlvisiaSilver.copy(alpha = 0.5f), fontSize = 10.sp)
        Spacer(Modifier.height(6.dp))
        LazyColumn(
            Modifier
                .fillMaxSize()
                .background(Color(0xFF070D14), RoundedCornerShape(12.dp))
                .padding(10.dp)
        ) {
            items(logs) { line ->
                Text(line, color = AlvisiaSilver, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
        }
    }
}

package com.alvsia.pro.ui.tool

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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
fun SubMenuScreen(
    moduleTitle: String,
    moduleId: Int,
    items: List<SubTool>,
    onBack: () -> Unit,
    onSelect: (SubTool) -> Unit
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(AlvisiaDeep)
            .statusBarsPadding()
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) {
                Text("<- BACK", color = AlvisiaCyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }
            Spacer(Modifier.weight(1f))
            Text(
                "%02d".format(moduleId),
                color = AlvisiaCyan,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )
        }
        Text(moduleTitle, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text("Select sub-tool", color = AlvisiaSilver.copy(alpha = 0.55f), fontSize = 12.sp)
        Spacer(Modifier.height(12.dp))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            itemsIndexed(items) { index, item ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color(0xFF0C1622))
                        .border(1.dp, AlvisiaBlue.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
                        .clickable { onSelect(item) }
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "%d.".format(index + 1),
                        color = AlvisiaCyan,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(item.title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(item.desc, color = AlvisiaSilver.copy(alpha = 0.55f), fontSize = 11.sp)
                        Text(item.guide, color = AlvisiaSilver.copy(alpha = 0.4f), fontSize = 9.sp, maxLines = 2)
                    }
                    Text(">", color = AlvisiaCyan, fontSize = 18.sp)
                }
            }
        }
    }
}

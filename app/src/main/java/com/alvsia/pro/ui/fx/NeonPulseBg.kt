package com.alvsia.pro.ui.fx

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import com.alvsia.pro.media.PulseAudio
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaRed
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun NeonPulseBackground(modifier: Modifier = Modifier) {
    val level by PulseAudio.level.collectAsState(0.15f)
    var tick by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(Unit) {
        val t0 = System.nanoTime()
        while (true) {
            withFrameNanos { now ->
                tick = ((now - t0) / 1_000_000_000f)
            }
        }
    }
    val pulse = level.coerceIn(0.08f, 1f)

    Canvas(modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height
        val cx = w / 2f
        val cy = h * 0.42f
        drawRect(Color(0xFF02050C))

        // ambient radial glow
        drawCircle(
            brush = Brush.radialGradient(
                listOf(
                    AlvisiaBlue.copy(alpha = 0.12f + pulse * 0.18f),
                    Color.Transparent
                ),
                center = Offset(cx, cy),
                radius = w * 0.55f
            ),
            radius = w * 0.55f,
            center = Offset(cx, cy)
        )

        // beat rings
        for (i in 0 until 5) {
            val r = w * (0.12f + i * 0.08f) * (0.85f + pulse * 0.35f)
            val a = (0.08f + pulse * 0.22f) * (1f - i * 0.12f)
            val col = when (i % 3) {
                0 -> AlvisiaCyan.copy(alpha = a)
                1 -> AlvisiaBlue.copy(alpha = a)
                else -> AlvisiaRed.copy(alpha = a * 0.7f)
            }
            drawCircle(
                color = col,
                radius = r,
                center = Offset(cx, cy),
                style = Stroke(width = 2f + pulse * 4f)
            )
        }

        // floating neon particles
        for (i in 0 until 60) {
            val seed = i * 17.13f
            val px = ((sin(tick * 0.35 + seed) * 0.5 + 0.5).toFloat() * w)
            val py = (((tick * (0.06f + (i % 5) * 0.015f) + seed * 0.1f) % 1.15f) * h)
            val sz = 1.5f + (i % 4) * 0.8f + pulse * 2f
            val a = 0.2f + pulse * 0.45f
            val c = if (i % 7 == 0) AlvisiaRed.copy(alpha = a * 0.8f)
            else if (i % 3 == 0) AlvisiaCyan.copy(alpha = a)
            else AlvisiaBlue.copy(alpha = a)
            drawCircle(c, sz, Offset(px, py))
        }

        // horizontal scan lines subtle
        val scanY = ((tick * 40f) % h)
        drawLine(
            color = AlvisiaCyan.copy(alpha = 0.06f + pulse * 0.08f),
            start = Offset(0f, scanY),
            end = Offset(w, scanY),
            strokeWidth = 2f
        )
    }
}

package com.alvsia.pro.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val AlvisiaBlue = Color(0xFF00A3FF)
val AlvisiaCyan = Color(0xFF00E5FF)
val AlvisiaSilver = Color(0xFFE8EEF6)
val AlvisiaDeep = Color(0xFF02050C)
val AlvisiaCard = Color(0xCC0A121C)
val AlvisiaRed = Color(0xFFFF2D55)
val AlvisiaMetal = Color(0xFF8FA3B8)
val AlvisiaGlow = Color(0xFF00B4FF)

private val DarkColors = darkColorScheme(
    primary = AlvisiaBlue,
    secondary = AlvisiaCyan,
    tertiary = AlvisiaRed,
    background = AlvisiaDeep,
    surface = AlvisiaCard,
    onPrimary = Color.White,
    onBackground = AlvisiaSilver,
    onSurface = AlvisiaSilver
)

@Composable
fun AlvisiaTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkColors, content = content)
}

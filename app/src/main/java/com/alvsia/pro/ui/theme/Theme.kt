package com.alvsia.pro.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val AlvisiaBlue = Color(0xFF42D6FF)
val AlvisiaCyan = Color(0xFF8AF7E8)
val AlvisiaSilver = Color(0xFFEAF2FA)
val AlvisiaDeep = Color(0xFF050912)
val AlvisiaCard = Color(0xE6111C2A)
val AlvisiaRed = Color(0xFFFF5477)
val AlvisiaMetal = Color(0xFF9CB3C9)
val AlvisiaGlow = Color(0xFF6C8CFF)

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

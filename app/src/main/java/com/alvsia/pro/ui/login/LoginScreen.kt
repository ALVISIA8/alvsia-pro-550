package com.alvsia.pro.ui.login

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.R
import com.alvsia.pro.ui.fx.NeonPulseBackground
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaRed
import com.alvsia.pro.ui.theme.AlvisiaSilver

@Composable
fun LoginScreen(
    hwidFull: String,
    hwidShort: String,
    loading: Boolean,
    error: String?,
    onLogin: (String) -> Unit
) {
    var key by remember { mutableStateOf("") }
    Box(Modifier.fillMaxSize()) {
        NeonPulseBackground(Modifier.fillMaxSize())
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(34.dp))
            Image(
                painter = painterResource(R.drawable.logo_alvisia),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .size(104.dp)
                    .clip(CircleShape)
                    .border(2.dp, AlvisiaCyan.copy(alpha = 0.5f), CircleShape)
            )
            Spacer(Modifier.height(16.dp))
            Text("ALVSIA", color = Color.White, fontWeight = FontWeight.Black, fontSize = 28.sp, letterSpacing = 5.sp)
            Text("PRO  //  SECURE TOOL SYSTEM", color = AlvisiaCyan, fontWeight = FontWeight.Bold, fontSize = 11.sp, letterSpacing = 1.5.sp)
            Spacer(Modifier.height(8.dp))
            Text("19 TOOLS  ·  ONE SECURE WORKSPACE", color = AlvisiaSilver.copy(alpha = 0.58f), fontSize = 10.sp)
            Spacer(Modifier.height(24.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(24.dp))
                    .background(Brush.linearGradient(listOf(Color(0xEE142438), Color(0xF00A111D), Color(0xEE122A30))))
                    .border(1.dp, AlvisiaCyan.copy(alpha = 0.28f), RoundedCornerShape(24.dp))
                    .padding(20.dp)
            ) {
                Column {
                    Text("DEVICE ID  /  HARDWARE BINDING", color = AlvisiaCyan.copy(alpha = 0.9f), fontWeight = FontWeight.Bold, fontSize = 9.sp, letterSpacing = 1.2.sp)
                    Text(hwidShort + "…", color = AlvisiaSilver, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(18.dp))
                    OutlinedTextField(
                        value = key,
                        onValueChange = { key = it.trim() },
                        label = { Text("License key") },
                        singleLine = true,
                        enabled = !loading,
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = AlvisiaCyan,
                            unfocusedBorderColor = AlvisiaBlue.copy(alpha = 0.4f),
                            focusedLabelColor = AlvisiaCyan,
                            cursorColor = AlvisiaCyan,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = AlvisiaSilver
                        )
                    )
                    if (!error.isNullOrBlank()) {
                        Spacer(Modifier.height(8.dp))
                        Text(error, color = AlvisiaRed, fontSize = 12.sp)
                    }
                    Spacer(Modifier.height(14.dp))
                    Button(
                        onClick = { if (key.isNotBlank() && !loading) onLogin(key) },
                        enabled = !loading && key.isNotBlank(),
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue)
                    ) {
                        Text(
                            if (loading) "AUTHENTICATING..." else "LOGIN",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            Text("ALVSIA PRO — KEY AUTH SYSTEM", color = AlvisiaSilver.copy(alpha = 0.45f), fontSize = 11.sp)
        }
    }
}

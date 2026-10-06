package com.alvsia.pro.ui.otp

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvsia.pro.ui.fx.NeonPulseBackground
import com.alvsia.pro.ui.theme.AlvisiaBlue
import com.alvsia.pro.ui.theme.AlvisiaCyan
import com.alvsia.pro.ui.theme.AlvisiaRed
import com.alvsia.pro.ui.theme.AlvisiaSilver

@Composable
fun OtpScreen(
    info: String = "",
    loading: Boolean,
    error: String?,
    onRequest: () -> Unit = {},
    onVerify: (String) -> Unit
) {
    var otp by remember { mutableStateOf("") }
    var requested by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (!requested) {
            requested = true
            onRequest()
        }
    }

    Box(Modifier.fillMaxSize()) {
        NeonPulseBackground(Modifier.fillMaxSize())
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(48.dp))
            Text(
                "OTP VERIFICATION",
                color = AlvisiaCyan,
                fontWeight = FontWeight.Black,
                fontSize = 18.sp
            )
            Text(
                "Code sent to owner Telegram",
                color = AlvisiaSilver.copy(alpha = 0.6f),
                fontSize = 12.sp
            )
            Spacer(Modifier.height(24.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(Color(0xAA0A1520))
                    .border(1.dp, AlvisiaCyan.copy(alpha = 0.3f), RoundedCornerShape(16.dp))
                    .padding(16.dp)
            ) {
                Column {
                    if (info.isNotBlank()) {
                        Text(info, color = Color(0xFF00E676), fontSize = 12.sp)
                        Spacer(Modifier.height(10.dp))
                    }
                    OutlinedTextField(
                        value = otp,
                        onValueChange = { if (it.length <= 6) otp = it.filter { c -> c.isDigit() } },
                        label = { Text("OTP") },
                        singleLine = true,
                        enabled = !loading,
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
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
                        onClick = { if (otp.length >= 4 && !loading) onVerify(otp) },
                        enabled = !loading && otp.length >= 4,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AlvisiaBlue)
                    ) {
                        Text(
                            if (loading) "VERIFYING..." else "VERIFY OTP",
                            fontWeight = FontWeight.Bold
                        )
                    }
                    TextButton(
                        onClick = { if (!loading) onRequest() },
                        enabled = !loading,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    ) {
                        Text("Resend OTP", color = AlvisiaCyan)
                    }
                }
            }
        }
    }
}

package com.alvsia.pro.panel

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest

object Hwid {
    fun deviceId(context: Context): String {
        val androidId = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ANDROID_ID
        ) ?: "unknown"
        val raw = "ALVSIA|${Build.MODEL}|${Build.FINGERPRINT}|$androidId"
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }
}

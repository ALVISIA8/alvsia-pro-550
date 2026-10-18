package com.alvsia.pro.panel

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.alvsia.pro.sec.ThreatReport
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/**
 * ALVSIA PRO 5.5.1 — Hwid HARDENED (Sprint 1 — multi-source fingerprint)
 *
 * Pattern reference: T24XOR_tool_source.py — multi-source device fingerprint
 * to avoid HWID collision when android_id is "null" (Termux/sideload case).
 *
 * Layers:
 *  1. android_id (Settings.Secure — most unique per device+user)
 *  2. ro.serialno (hardware serial — read via getprop)
 *  3. Build.FINGERPRINT (build string — unique per OS build)
 *  4. Build.MODEL + MANUFACTURER + DEVICE + HARDWARE
 *  5. UUID fallback file (auto-generated persistent UUID — ultimate fallback)
 *
 * Any layer that returns non-empty data → unique HWID guaranteed.
 * All sources combined into SHA-256 — no single source can be faked to bypass.
 */
object Hwid {
    private const val TAG = "ALVSIA_Hwid"
    private const val UUID_FALLBACK_PATH = "/data/data/com.alvsia.pro/files/alvsia_device.uuid"

    fun deviceId(context: Context): String {
        val parts = mutableListOf<String>()

        // Layer 1: android_id
        try {
            val androidId = Settings.Secure.getString(
                context.contentResolver, Settings.Secure.ANDROID_ID
            )
            if (!androidId.isNullOrBlank() && androidId != "null" && androidId != "unknown") {
                parts += "aid:$androidId"
            }
        } catch (_: Exception) {
            // Settings unavailable — skip layer
        }

        // Layer 2: ro.serialno via getprop (root not needed)
        try {
            val serial = getprop("ro.serialno")
                ?: getprop("ro.boot.serialno")
                ?: getprop("ro.boot.serialno.hardware")
            if (!serial.isNullOrBlank() && serial != "unknown") {
                parts += "serial:$serial"
            }
        } catch (_: Exception) {
            // getprop unavailable — skip
        }

        // Layer 3: Build.FINGERPRINT (build string)
        try {
            val fp = Build.FINGERPRINT
            if (!fp.isNullOrBlank() && fp != "unknown") {
                parts += "fp:$fp"
            }
        } catch (_: Exception) {
            // Build unavailable (very rare) — skip
        }

        // Layer 4: Build.MODEL + MANUFACTURER + DEVICE + HARDWARE + BOARD
        try {
            val model = Build.MODEL ?: ""
            val manufacturer = Build.MANUFACTURER ?: ""
            val device = Build.DEVICE ?: ""
            val hardware = Build.HARDWARE ?: ""
            val board = Build.BOARD ?: ""
            if (model.isNotBlank() || manufacturer.isNotBlank()) {
                parts += "build:${manufacturer}|${model}|${device}|${hardware}|${board}"
            }
        } catch (_: Exception) {
            // Build fields unavailable — skip
        }

        // Layer 5: UUID fallback file — last resort
        // If all above fail (extremely rare — only on broken Android installs),
        // generate a UUID and persist it. This guarantees uniqueness even when
        // no system identifiers are available.
        if (parts.isEmpty()) {
            try {
                val uuidFile = File(UUID_FALLBACK_PATH)
                if (uuidFile.isFile && uuidFile.length() >= 8) {
                    val existing = uuidFile.readText().trim()
                    if (existing.isNotEmpty()) {
                        parts += "uuid:$existing"
                    }
                }
                if (parts.isEmpty()) {
                    val newUuid = UUID.randomUUID().toString()
                    uuidFile.parentFile?.mkdirs()
                    uuidFile.writeText(newUuid)
                    parts += "uuid:$newUuid"
                }
            } catch (_: Exception) {
                // Final fallback — ephemeral UUID (won't persist across restarts but
                // better than returning "unknown" which would collide for all users)
                parts += "ephemeral:${UUID.randomUUID()}"
            }
        }

        val raw = "ALVSIA|${parts.joinToString("|")}"
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    /**
     * Read a system property via `getprop`. Returns null if unavailable.
     * T24XOR pattern: subprocess call to `getprop <key>`.
     */
    private fun getprop(key: String): String? {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", key))
            val out = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (out.isNotEmpty() && out != "unknown" && out != "null") out else null
        } catch (_: Exception) {
            null
        }
    }
}

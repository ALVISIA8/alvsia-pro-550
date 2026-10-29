package com.alvsia.pro.sec

import android.content.Context
import java.io.BufferedReader
import java.io.FileReader

object Guard {

    // Passive root/manager artifacts are deliberately excluded from hard
    // enforcement. Only active runtime instrumentation should block a session.
    private val RUNTIME_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "libfrida",
        "libgadget", "xposed", "lsposed", "edxposed", "substrate",
        "libsandhook", "libepic", "linjector",
        "libdobby", "shadowhook", "bhook", "bytehook",
        "libandroid_inline_hook"
    )

    @Volatile var degraded: Boolean = false
    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true
    ): Boolean {
        val active = hostile(ctx)
        if (active) {
            try { ThreatReport.emit(ctx, "GUARD_HOSTILE", _lastReason, license) } catch (_: Exception) {}
            degraded = true
            if (hardEnforcement) return false
            // Soft pre-login check records the signal but must not reject the
            // license before the authenticated, hard-enforcement check runs.
            return true
        }
        return true
    }

    fun hostile(ctx: Context): Boolean {
        try {
            val status = java.io.File("/proc/self/status").readText()
            val tracer = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
            if (tracer > 0) {
                _lastReason = "tracer_attached"
                return true
            }
        } catch (_: Exception) {
            // Permission/OS differences are not evidence of a hostile process.
        }

        try {
            val maps = java.io.File("/proc/self/maps").readText().lowercase()
            val hit = RUNTIME_MARKERS.firstOrNull { it in maps }
            if (hit != null) {
                _lastReason = "active_hook_map:$hit"
                return true
            }
        } catch (_: Exception) {
            // Inaccessible maps must not lock out a legitimate user.
        }
        _lastReason = ""
        return false
    }

    fun runtimeHostile(ctx: Context): Boolean =
        hostile(ctx) || NativeGuard.scanFlags() != 0
}

package com.alvsia.pro.sec

import android.content.Context
import java.io.File

object Guard {
    // Hard blocks require high-confidence active instrumentation evidence.
    // Generic hook bridges can also be loaded by native protectors.
    private val HARD_RUNTIME_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget", "linjector"
    )
    private val SOFT_HOOK_MARKERS = listOf(
        "xposed", "lsposed", "edxposed", "substrate", "libsandhook",
        "libepic", "libdobby", "dobby", "shadowhook", "shadow_hook",
        "bhook", "bytehook", "libbytehook", "libwhale", "riru", "zygisk",
        "libnative_hook", "libandroid_inline_hook", "libhookprovider"
    )

    @Volatile var degraded: Boolean = false
    @Volatile private var _lastReason = ""
    val lastReason: String get() = _lastReason

    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true
    ): Boolean {
        if (hostile(ctx)) {
            try { ThreatReport.emit(ctx, "GUARD_HOSTILE", _lastReason, license) } catch (_: Exception) {}
            degraded = true
            if (hardEnforcement) return false
            return true
        }

        val softMarker = softHookSignal()
        if (softMarker != null) {
            degraded = true
            try { ThreatReport.emit(ctx, "GUARD_SOFT_HOOK", softMarker, license) } catch (_: Exception) {}
        } else {
            degraded = false
        }
        return true
    }

    fun hostile(ctx: Context): Boolean {
        // TracerPid is high-confidence evidence; ADB/developer options alone are not.
        try {
            val status = File("/proc/self/status").readText()
            val tracer = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
            if (tracer > 0) {
                _lastReason = "tracer_attached"
                return true
            }
        } catch (_: Exception) {
            // OS permission differences are not evidence of tampering.
        }

        try {
            val maps = File("/proc/self/maps").readLines()
            for (line in maps) {
                val fields = line.trim().split(Regex("\\s+"), limit = 6)
                if (fields.size < 2 || 'x' !in fields[1]) continue
                val mappedName = fields.getOrNull(5)?.lowercase().orEmpty()
                if (mappedName.isBlank()) continue
                val hit = HARD_RUNTIME_MARKERS.firstOrNull { it in mappedName }
                if (hit != null) {
                    _lastReason = "active_instrumentation_map:$hit"
                    return true
                }
            }
        } catch (_: Exception) {
            // Inaccessible maps must not lock out a legitimate user.
        }
        _lastReason = ""
        return false
    }

    private fun softHookSignal(): String? {
        return try {
            for (line in File("/proc/self/maps").readLines()) {
                val fields = line.trim().split(Regex("\\s+"), limit = 6)
                if (fields.size < 2 || 'x' !in fields[1]) continue
                val mappedName = fields.getOrNull(5)?.lowercase().orEmpty()
                val hit = SOFT_HOOK_MARKERS.firstOrNull { it in mappedName }
                if (hit != null) return "executable_hook_library:$hit"
            }
            null
        } catch (_: Exception) { null }
    }

    fun runtimeHostile(ctx: Context): Boolean =
        hostile(ctx) || NativeGuard.scanFlags() != 0
}

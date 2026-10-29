package com.alvsia.pro.sec

import android.content.Context
import java.io.File

object Guard {

    // Only treat a marker in an executable mapping as active instrumentation.
    // Looking at the whole maps file can produce false positives from unrelated
    // non-executable mappings and metadata.
    private val RUNTIME_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget", "xposed", "lsposed", "edxposed",
        "substrate", "libsandhook", "libepic", "linjector",
        "libdobby", "shadowhook", "shadow_hook", "bhook", "bytehook",
        "libandroid_inline_hook"
    )

    @Volatile var degraded: Boolean = false
    @Volatile private var _lastReason = ""
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
            // A soft pre-login check records signals without rejecting the license
            // before the authenticated hard-enforcement check runs.
            return true
        }
        degraded = false
        return true
    }

    fun hostile(ctx: Context): Boolean {
        // TracerPid > 0 means this process is actually being traced; developer
        // options or ADB being enabled by themselves are not a block condition.
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
            // Procfs permission/OS differences are not evidence of a hostile process.
        }

        try {
            val maps = File("/proc/self/maps").readLines()
            for (line in maps) {
                // Linux maps fields: address, permissions, offset, device, inode,
                // then optional pathname. Match only executable mappings and their
                // pathname (including named anonymous executable mappings).
                val fields = line.trim().split(Regex("\\s+"), limit = 6)
                if (fields.size < 2 || 'x' !in fields[1]) continue
                val mappedName = fields.getOrNull(5)?.lowercase().orEmpty()
                if (mappedName.isBlank()) continue
                val hit = RUNTIME_MARKERS.firstOrNull { it in mappedName }
                if (hit != null) {
                    _lastReason = "active_hook_map:$hit"
                    return true
                }
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

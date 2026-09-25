package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Multi-signal hostile environment detection.
 * Patterns inspired by common open anti-debug/anti-hook checklists
 * (Frida/Xposed maps, tracer pid, debug flags, classic root paths).
 */
object Guard {
    @Volatile var degraded: Boolean = false

    private val MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "substrate", "libsubstrate", "libsandhook", "libepic",
        "riru", "zygisk", "perseus", "agent-arm", "gadget",
        "magisk", "libhook", "linjector", "libsubstrate.so"
    )

    private val ROOT_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon",
        "/system/xbin/busybox", "/data/adb/magisk", "/sbin/.magisk"
    )

    private val HOOK_LIBS = listOf(
        "libsubstrate.so", "libxposed_art.so", "libFridaGadget.so",
        "libsandhook.so", "libepic.so"
    )

    fun hostile(): Boolean {
        if (Debug.isDebuggerConnected()) return true
        if (Debug.waitingForDebugger()) return true
        if (tracerAttached()) return true
        if (mapsHits().isNotEmpty()) return true
        if (FridaProbe.signals().isNotEmpty()) return true
        if (suspiciousProperties()) return true
        return false
    }

    fun checkAndReport(ctx: Context, license: String = "") {
        val reasons = mutableListOf<String>()
        if (Debug.isDebuggerConnected()) reasons += "debugger"
        if (Debug.waitingForDebugger()) reasons += "wait_debugger"
        if (tracerAttached()) reasons += "tracer_pid"
        val m = mapsHits()
        if (m.isNotEmpty()) reasons += "maps:" + m.joinToString(",")
        val fr = FridaProbe.signals()
        if (fr.isNotEmpty()) reasons += fr
        if (rootPresent()) reasons += "root_paths"
        if (suspiciousProperties()) reasons += "debug_props"
        val tamper = Tamper.evaluate(ctx)
        if (!tamper.ok) reasons += tamper.reasons.map { "tamper:$it" }
        if (reasons.isNotEmpty()) {
            degraded = true
            ThreatReport.emit(ctx, "HOSTILE_ENV", reasons.joinToString(" | "), license)
            // Hard: instrumentation / sig / debugger always lock session
            if (reasons.any {
                    it.startsWith("maps:") || it == "debugger" || it == "tracer_pid" ||
                        it.startsWith("tamper:") || it.contains("frida", true)
                }) {
                SessionGate.onThreat()
            }
        }
    }

    private fun tracerAttached(): Boolean {
        return try {
            val t = File("/proc/self/status").readText()
            val line = t.lineSequence().firstOrNull { it.startsWith("TracerPid:") } ?: return false
            (line.substringAfter(":").trim().toIntOrNull() ?: 0) > 0
        } catch (_: Exception) {
            false
        }
    }

    private fun mapsHits(): List<String> {
        return try {
            val text = File("/proc/self/maps").readText().lowercase()
            MAP_MARKERS.filter { it in text }.distinct()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun rootPresent(): Boolean {
        return ROOT_PATHS.any { File(it).exists() }
    }

    private fun suspiciousProperties(): Boolean {
        return try {
            val keys = listOf("ro.debuggable", "ro.secure", "service.adb.root")
            // read via getprop not always available; check build tags
            val tags = Build.TAGS ?: ""
            tags.contains("test-keys") || Build.FINGERPRINT.contains("generic")
        } catch (_: Exception) {
            false
        }
    }
}

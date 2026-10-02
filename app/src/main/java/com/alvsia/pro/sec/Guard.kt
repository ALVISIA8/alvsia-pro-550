package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * ALVISIA PRO 5.5.0 — Guard HARDENED
 * Fast hostile-check used at tool gate and inline hot-path.
 * Routes through all sub-probes for a unified boolean + reason list.
 */
object Guard {
    @Volatile var degraded: Boolean = false

    // ── Maps markers (combined from all known hook frameworks) ────────
    private val MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "substrate", "libsubstrate", "libsandhook", "libepic",
        "riru", "zygisk", "perseus", "linjector",
        "agent-arm", "gadget", "magisk", "libhook",
        "libsubstrate.so", "libdobby", "dobby",
        "shadowhook", "bhook", "bytehook",
        "com.taichi.hookprovider", "whale_arm"
    )

    private val ROOT_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon",
        "/data/adb/magisk", "/sbin/.magisk",
        "/data/adb/su", "/system/app/KernelSU.apk"
    )

    /** Fast check — used in tool gate hot-path (< 5 ms target). */
    fun hostile(): Boolean {
        if (Debug.isDebuggerConnected()) return true
        if (Debug.waitingForDebugger()) return true
        if (tracerAttached()) return true
        if (mapsHits().isNotEmpty()) return true
        if (FridaProbe.signals().isNotEmpty()) return true
        if (suspiciousProperties()) return true
        return false
    }

    /** Full check with reason list — used at session start and tick. */
    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true,
    ): Boolean {
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
        // Integrity bomb
        val bomb = IntegrityBomb.evaluate(ctx)
        if (!bomb.clean) reasons += bomb.reasons.map { "bomb:$it" }
        // Memory dump
        val memSig = MemoryGuard.allSignals()
        if (memSig.isNotEmpty()) reasons += memSig
        // Network proxy / MITM
        val netSig = NetworkGuard.signals(ctx)
        if (netSig.isNotEmpty()) reasons += netSig.map { "net:$it" }

        if (reasons.isNotEmpty()) {
            degraded = true
            ThreatReport.emit(ctx, "HOSTILE_ENV", reasons.joinToString(" | "), license)
            val hard = reasons.any {
                it.startsWith("maps:") || it == "debugger" || it == "tracer_pid" ||
                        // tamper:sig_unreadable excluded: APK hardening tools can temporarily
                        // make the signing block unreadable via standard PackageManager APIs.
                        // sig_mismatch (wrong cert) and all other tamper flags remain hard.
                        (it.startsWith("tamper:") && it != "tamper:sig_unreadable") ||
                        it.contains("frida", true) ||
                        it.startsWith("bomb:cert") ||
                        // bomb:dex_size_anomaly excluded: hardening replaces classes.dex
                        // with a stub loader; DEX_MIN=0 already prevents this, but guard here too.
                        (it.startsWith("bomb:dex") && !it.startsWith("bomb:dex_size_anomaly")) ||
                        it.startsWith("mem_open") || it.startsWith("ptrace")
            }
            if (hard && hardEnforcement) SessionGate.onThreat()
            return !hard
        }
        return true
    }

    private fun tracerAttached(): Boolean {
        return try {
            val status = File("/proc/self/status").readText()
            val line = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?: return false
            (line.substringAfter(":").trim().toIntOrNull() ?: 0) > 0
        } catch (_: Exception) { false }
    }

    private fun mapsHits(): List<String> = try {
        val text = File("/proc/self/maps").readText().lowercase()
        MAP_MARKERS.filter { it in text }.distinct()
    } catch (_: Exception) { emptyList() }

    private fun rootPresent(): Boolean = ROOT_PATHS.any { File(it).exists() }

    private fun suspiciousProperties(): Boolean = try {
        val tags = Build.TAGS ?: ""
        tags.contains("test-keys") || Build.FINGERPRINT.contains("generic")
    } catch (_: Exception) { false }
}

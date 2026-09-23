package com.alvsia.pro.sec

import android.content.Context
import android.os.Debug
import java.io.File

object Guard {
    private val MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "substrate", "libsubstrate", "libsandhook", "libepic",
        "riru", "zygisk", "perseus", "agent-arm", "gadget"
    )

    @Volatile
    var degraded: Boolean = false

    fun hostile(): Boolean {
        if (Debug.isDebuggerConnected()) return true
        if (tracerAttached()) return true
        if (mapsHits().isNotEmpty()) return true
        if (FridaProbe.signals().isNotEmpty()) return true
        return false
    }

    fun checkAndReport(ctx: Context, license: String = "") {
        val reasons = mutableListOf<String>()
        if (Debug.isDebuggerConnected()) reasons += "debugger"
        if (tracerAttached()) reasons += "tracer_pid"
        val m = mapsHits()
        if (m.isNotEmpty()) reasons += "maps:" + m.joinToString(",")
        val fr = FridaProbe.signals()
        if (fr.isNotEmpty()) reasons += fr
        val tamper = Tamper.evaluate(ctx)
        if (!tamper.ok) reasons += tamper.reasons.map { "tamper:$it" }
        if (reasons.isNotEmpty()) {
            degraded = reasons.any {
                it.startsWith("maps:") || it == "debugger" || it == "tracer_pid" ||
                    it.startsWith("path:") || it.startsWith("port:") ||
                    it.contains("sig_mismatch")
            }
            ThreatReport.emit(ctx, "HOSTILE_ENV", reasons.joinToString(" | "), license)
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
}

package com.alvsia.pro.sec

import android.content.Context
import java.io.BufferedReader
import java.io.FileReader

object Guard {

    /**
     * R5.4 FINAL FIX:
     * MAP_MARKERS hanya berisi ACTIVE HOOK INJECTORS — library yang harus
     * di-inject ke dalam process untuk berfungsi (Frida agent, Xposed, Substrate,
     * Dobby, ShadowHook, dll).
     *
     * DIHAPUS dari MAP_MARKERS:
     *   - magisk, shamiko, riru, zygisk  → root framework markers
     *   - lspatch, lsposed, edxposed     → package managers (tidak inject ke maps)
     *
     * Root detection sudah ada di EnvProbe → soft signals → telemetry only.
     * Double-counting root sebagai hard signal menyebabkan Guard.degraded=true
     * pada semua device Magisk meskipun tidak ada instrumentation aktif.
     */
    private val MAP_MARKERS = listOf(
        // Frida
        "frida-agent", "frida_agent", "frida-gadget", "frida_gadget",
        "libfrida", "libgadget",
        // Xposed/Substrate aktif (hanya kalau benar-benar di-inject)
        "com.saurik.substrate", "libsubstrate", "substrate32", "substrate64",
        "libsandhook", "libepic", "epic-arm", "epic-arm64",
        // Hook libraries aktif
        "libhook", "libdobby", "dobby",
        "libandroid_inline_hook",
        "shadowhook", "shadow_hook",
        "bhook", "bytehook",
        "linjector",
        "agent-arm", "agent-arm64",
        "turbo_trace", "whale_arm",
        "com.taichi.hookprovider"
        // NOTE: magisk, shamiko, zygisk, riru, lspatch, lsposed, edxposed DIHAPUS
        // karena ini root framework markers, bukan active hook injectors.
        // Root sudah di-handle oleh EnvProbe sebagai soft/telemetry signal.
    )

    @Volatile var degraded: Boolean = false

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    /**
     * R5.4: degraded hanya di-set saat hardEnforcement=true (genuine hard call).
     * Soft callers (hardEnforcement=false) emit telemetry tapi tidak poison gate.
     */
    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true
    ): Boolean {
        val hostile = hostile(ctx)
        if (hostile) {
            ThreatReport.emit(ctx, "GUARD_HOSTILE", _lastReason, license)
            if (hardEnforcement) {
                degraded = true
                return false
            }
        }
        return !hostile
    }

    fun hostile(ctx: Context): Boolean {
        if (tracerPidAttached()) { _lastReason = "tracer_attached"; return true }
        if (hookInMaps()) { _lastReason = "hook_in_maps:$_mapsHit"; return true }
        _lastReason = ""
        return false
    }

    private var _mapsHit = ""

    private fun tracerPidAttached(): Boolean {
        return try {
            val br = BufferedReader(FileReader("/proc/self/status"))
            var line: String?
            var found = false
            while (br.readLine().also { line = it } != null) {
                if (line!!.startsWith("TracerPid:")) {
                    val pid = line!!.substringAfter(":").trim().toLongOrNull() ?: 0L
                    found = pid != 0L
                    break
                }
            }
            br.close()
            found
        } catch (_: Exception) { false }
    }

    private fun hookInMaps(): Boolean {
        return try {
            val br = BufferedReader(FileReader("/proc/self/maps"))
            var line: String?
            var found = false
            while (br.readLine().also { line = it } != null) {
                val lower = line!!.lowercase()
                for (marker in MAP_MARKERS) {
                    if (lower.contains(marker)) {
                        _mapsHit = marker
                        found = true
                        break
                    }
                }
                if (found) break
            }
            br.close()
            found
        } catch (_: Exception) { false }
    }
}

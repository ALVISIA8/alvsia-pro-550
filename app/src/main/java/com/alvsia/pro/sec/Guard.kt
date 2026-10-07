package com.alvsia.pro.sec

import android.content.Context
import java.io.BufferedReader
import java.io.FileReader

object Guard {

    // rsprotect = Reark protector native lib — intentionally whitelisted
    private val MAP_MARKERS = listOf(
        "frida", "xposed", "substrate", "dobby",
        "lspatch", "lsposed", "zygisk", "edxposed",
        "riru", "magisk", "shamiko",
        "hookzz", "whale", "sandhook",
        "epic", "dexposed", "andfix"
    )

    @Volatile var degraded: Boolean = false

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    /**
     * Full backward-compatible API used by AlvisiaApp, MainActivity, RaspEngine.
     *
     * R5.4 FIX: Guard.degraded is only set when hardEnforcement=true (i.e. the
     * caller is treating this as an instrumentation-class hard signal).
     * When hardEnforcement=false the caller has already decided that hostile()
     * results are soft / telemetry-only — setting degraded here would block tools
     * on any rooted or Magisk-hiding device even though the R5.4 intent is to
     * allow legitimate users on rooted hardware through the session gate.
     *
     * Hard instrumentation signals (FridaProbe live hits, debugger, tracerPid)
     * continue to set degraded=true via RaspEngine.tick() independently.
     */
    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true
    ): Boolean {
        val hostile = hostile(ctx)
        if (hostile) {
            ThreatReport.emit(ctx, "GUARD_HOSTILE", _lastReason, license)
            // Only elevate degraded state when the caller treats this as hard.
            // Soft callers (hardEnforcement=false) report telemetry but must not
            // pre-poison the SessionGate for what may be a clean user device.
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

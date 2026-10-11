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

    // Only active instrumentation/debugging indicators are enforced on every
    // dispatch. Root-management markers alone (Magisk/Zygisk/Shamiko) remain
    // report-only to avoid breaking legitimate rooted-device users.
    private val RUNTIME_MARKERS = listOf(
        "frida", "xposed", "substrate", "dobby",
        "lspatch", "lsposed", "edxposed",
        "hookzz", "whale", "sandhook", "epic", "dexposed", "andfix"
    )

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    /**
     * Full backward-compatible API used by AlvisiaApp, MainActivity, RaspEngine.
     * hardEnforcement=false → return false on hostile but do NOT crash/kill.
     */
    fun checkAndReport(
        ctx: Context,
        license: String = "",
        hardEnforcement: Boolean = true
    ): Boolean {
        val hostile = hostile(ctx)
        if (hostile) {
            ThreatReport.emit(ctx, "GUARD_HOSTILE", _lastReason, license)
            degraded = true
            if (hardEnforcement) return false
        }
        return !hostile
    }

    fun runtimeHostile(ctx: Context): Boolean {
        if (tracerPidAttached()) { _lastReason = "tracer_attached"; return true }
        if (hookInMaps(RUNTIME_MARKERS)) { _lastReason = "runtime_hook_in_maps:" + _mapsHit; return true }
        _lastReason = ""
        return false
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

    private fun hookInMaps(markers: List<String> = MAP_MARKERS): Boolean {
        return try {
            val br = BufferedReader(FileReader("/proc/self/maps"))
            var line: String?
            var found = false
            while (br.readLine().also { line = it } != null) {
                val lower = line!!.lowercase()
                for (marker in markers) {
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

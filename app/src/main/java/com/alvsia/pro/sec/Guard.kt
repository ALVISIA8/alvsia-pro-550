package com.alvsia.pro.sec

import android.content.Context
import java.io.BufferedReader
import java.io.FileReader

object Guard {

    // Maps markers that indicate hook frameworks
    // rsprotect is Reark's native lib — whitelisted (our own protector)
    private val MAP_MARKERS = listOf(
        "frida", "xposed", "substrate", "dobby",
        "lspatch", "lsposed", "zygisk", "edxposed",
        "riru", "magisk", "shamiko",
        "hookzz", "whale", "sandhook",
        "epic", "dexposed", "andfix"
        // NOTE: "rsprotect" intentionally excluded — it is our own Reark protector
    )

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

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
        } catch (e: Exception) { false }
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
        } catch (e: Exception) { false }
    }
}

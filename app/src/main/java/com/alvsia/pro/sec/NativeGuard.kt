package com.alvsia.pro.sec

import java.io.File

/**
 * ALVISIA PRO 5.5.0 — NativeGuard HARDENED
 *
 * Bridges Kotlin RASP to the native librasp_guard.so layer.
 * If the native lib is NOT present (debug/CI build), falls back to
 * pure-Kotlin probes so compile always succeeds.
 *
 * JNI contract (librasp_guard.so implements these):
 *   native fun nativeScanFlags(): Int
 *     Bit 0: TracerPid > 0
 *     Bit 1: /proc/self/maps Frida marker found
 *     Bit 2: ptrace(PTRACE_TRACEME) returns error (already traced)
 *     Bit 3: hardware breakpoint register non-zero (GDB/IDA trace)
 *     Bit 4: inline hook in libdvm / libart .text section detected
 *     Bit 5: /proc/self/status CapEff == 0x3fffffffff (overgranted)
 *     Bit 6: self mem integrity hash mismatch (librasp_guard own page)
 *     Bit 7: timing-based ptrace detection (RDTSC delta)
 *
 *   native fun nativeWipe(buf: ByteArray): Unit
 *   native fun nativeAntiDump(): Int   — 0=clean, >0=dump attempt
 */
object NativeGuard {

    private var nativeLoaded = false

    init {
        try {
            System.loadLibrary("rasp_guard")
            nativeLoaded = true
        } catch (_: UnsatisfiedLinkError) {
            // Native lib not present — pure Kotlin fallback
        }
    }

    // ── JNI stubs (implemented in librasp_guard.so) ──────────────────
    private external fun nativeScanFlags(): Int
    private external fun nativeWipe(buf: ByteArray)
    private external fun nativeAntiDump(): Int
    private external fun nativeSealSeed(): ByteArray

    // ── Public API ────────────────────────────────────────────────────

    fun scanFlags(): Int {
        if (!nativeLoaded) return fallbackFlags()
        return try { nativeScanFlags() } catch (_: Exception) { fallbackFlags() }
    }

    fun sealSeedHex(): String {
        if (!nativeLoaded) throw IllegalStateException("native security library unavailable")
        return nativeSealSeed().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    fun antiDump(): Int {
        if (!nativeLoaded) return 0
        return try { nativeAntiDump() } catch (_: Exception) { 0 }
    }

    fun wipe(buf: ByteArray?) {
        buf ?: return
        if (nativeLoaded) {
            try { nativeWipe(buf); return } catch (_: Exception) {}
        }
        buf.fill(0)
    }

    fun flagsToReasons(f: Int): List<String> {
        if (f == 0) return emptyList()
        val r = mutableListOf<String>()
        if (f and 0x01 != 0) r += "n_tracer_pid"
        if (f and 0x02 != 0) r += "n_maps_frida"
        if (f and 0x04 != 0) r += "n_ptrace_error"
        if (f and 0x08 != 0) r += "n_hw_breakpoint"
        if (f and 0x10 != 0) r += "n_inline_hook"
        if (f and 0x20 != 0) r += "n_cap_overgranted"
        if (f and 0x40 != 0) r += "n_self_hash_mismatch"
        if (f and 0x80 != 0) r += "n_timing_ptrace"
        return r
    }

    // ── Kotlin fallback when native lib absent ────────────────────────

    private fun fallbackFlags(): Int {
        var flags = 0
        try {
            val status = File("/proc/self/status").readText()
            val tpid = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
            if (tpid > 0) flags = flags or 0x01
        } catch (_: Exception) {}
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            if ("frida" in maps || "gadget" in maps || "xposed" in maps) flags = flags or 0x02
        } catch (_: Exception) {}
        return flags
    }
}

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
    private external fun nativeSealSeed(): ByteArray?

    // ── Public API ────────────────────────────────────────────────────

    fun scanFlags(): Int {
        if (!nativeLoaded) return fallbackFlags()
        return try { nativeScanFlags() } catch (_: Exception) { fallbackFlags() }
    }

    fun antiDump(): Int {
        if (!nativeLoaded) return 0
        return try { nativeAntiDump() } catch (_: Exception) { 0 }
    }

    fun wipe(buf: ByteArray?) {
        buf ?: return
        if (NativeGuard.isNativeLoaded()) {
            try { nativeWipe(buf); return } catch (_: Exception) {}
        }
        buf.fill(0)
    }

    /**
     * Static bridge for Chaquopy. Without @JvmStatic, Kotlin `object` methods
     * are exposed as instance methods and Chaquopy passes the payload as `this`,
     * producing `Unbound method ... must be called with NativeGuard instance`.
     */
    @JvmStatic
    fun decryptSealedPayload(payload: ByteArray, buildId: String): ByteArray? {
        if (payload.size < 8 + 12 + 16 || buildId.isBlank() || buildId.length > 128) return null
        val magic = "ALVSEAL2".toByteArray(Charsets.UTF_8)
        if (!payload.copyOfRange(0, 8).contentEquals(magic)) return null
        val seed = try { nativeSealSeed() } catch (_: Throwable) { null } ?: return null
        if (seed.size != 32) { seed.fill(0); return null }
        return try {
            val certDigest = hexToBytes("99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c")
            val buildBytes = buildId.toByteArray(Charsets.UTF_8)
            val material = ByteArray(seed.size + certDigest.size + buildBytes.size)
            System.arraycopy(seed, 0, material, 0, seed.size)
            System.arraycopy(certDigest, 0, material, seed.size, certDigest.size)
            System.arraycopy(buildBytes, 0, material, seed.size + certDigest.size, buildBytes.size)
            val keyBytes = java.security.MessageDigest.getInstance("SHA-256").digest(material)
            material.fill(0)
            val iv = payload.copyOfRange(8, 20)
            val body = payload.copyOfRange(20, payload.size)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(keyBytes, "AES"), javax.crypto.spec.GCMParameterSpec(128, iv))
            cipher.updateAAD(magic)
            cipher.doFinal(body)
        } catch (_: Throwable) {
            null
        } finally {
            seed.fill(0)
        }
    }

    /** Per-build key for ALVSA1 asset envelopes; key derivation stays out of Python. */
    @JvmStatic
    fun assetSealKey(): ByteArray? {
        val seed = try { nativeSealSeed() } catch (_: Throwable) { null } ?: return null
        if (seed.size != 32) { seed.fill(0); return null }
        return try {
            val certDigest = hexToBytes("99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c")
            val label = "ALV-ASSET-v2".toByteArray(Charsets.UTF_8)
            val material = ByteArray(seed.size + certDigest.size + label.size)
            System.arraycopy(seed, 0, material, 0, seed.size)
            System.arraycopy(certDigest, 0, material, seed.size, certDigest.size)
            System.arraycopy(label, 0, material, seed.size + certDigest.size, label.size)
            try { java.security.MessageDigest.getInstance("SHA-256").digest(material) }
            finally { material.fill(0) }
        } catch (_: Throwable) {
            null
        } finally {
            seed.fill(0)
        }
    }

    private fun hexToBytes(value: String): ByteArray = ByteArray(value.length / 2) { i ->
        ((value[i * 2].digitToInt(16) shl 4) or value[i * 2 + 1].digitToInt(16)).toByte()
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

    fun isNativeLoaded(): Boolean = nativeLoaded
}

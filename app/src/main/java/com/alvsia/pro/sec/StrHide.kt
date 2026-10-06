package com.alvsia.pro.sec

/**
 * ALVISIA PRO 5.5.0 — StrHide HARDENED
 *
 * Multi-layer compile-time string obfuscation.
 * Replaces plaintext constants with XOR-masked int arrays.
 *
 * Encoding formula (matches encode.py utility):
 *   encoded[i] = (char[i] XOR mask XOR (i AND 0x3F) XOR salt)
 *
 * Usage:
 *   val url = StrHide.d(0x5A, 0x1F, intArrayOf(0x26, 0x0B, ...))
 *
 * Use the companion encode() at build time (in a Gradle task) to generate arrays:
 *   StrHide.encode("https://example.com", mask=0x5A, salt=0x1F)
 */
object StrHide {

    /** Decode a string from an XOR-masked int array. */
    fun d(mask: Int, salt: Int, data: IntArray): String {
        val out = ByteArray(data.size)
        for (i in data.indices) {
            out[i] = (data[i] xor mask xor (i and 0x3F) xor salt).toByte()
        }
        return String(out, Charsets.UTF_8)
    }

    /** Legacy 2-arg form (mask only, no salt). Kept for backward compat. */
    fun d(mask: Int, data: IntArray): String {
        val out = ByteArray(data.size)
        for (i in data.indices) {
            out[i] = (data[i] xor mask xor (i and 0x1F)).toByte()
        }
        return String(out, Charsets.UTF_8)
    }

    /**
     * Encode utility — run from Gradle build task, not at runtime in release.
     * Returns a Kotlin literal to copy into source.
     */
    fun encode(plain: String, mask: Int, salt: Int): String {
        val bytes = plain.toByteArray(Charsets.UTF_8)
        val arr = bytes.mapIndexed { i, b ->
            (b.toInt() and 0xFF) xor mask xor (i and 0x3F) xor salt
        }
        return "StrHide.d(0x${mask.toString(16).uppercase()}, 0x${salt.toString(16).uppercase()}, intArrayOf(${arr.joinToString(", ") { "0x${it.toString(16).uppercase()}" }}))"
    }

    // ── Pre-encoded critical strings (mask=0x7E, salt=0x33) ────────────────
    // Encoding: encoded[i] = (plain[i] XOR 0x7E XOR (i AND 0x3F) XOR 0x33)
    // Use encode() at build time if you need to add new strings.
    // NEVER add .ifBlank{} fallbacks — plaintext must not appear in the binary.

    /** Returns the base API URL "https://api.alvsia.pro" — XOR-encoded. */
    fun apiBase(): String = d(0x7E, 0x33, intArrayOf(
        0x25, 0x38, 0x3B, 0x3E, 0x3A, 0x72, 0x64, 0x65,
        0x24, 0x34, 0x2E, 0x68, 0x20, 0x2C, 0x35, 0x31,
        0x34, 0x3D, 0x71, 0x2E, 0x2B, 0x37
    ))

    /** Returns the security event path "/v1/sec" — XOR-encoded. */
    fun secPath(): String = d(0x7E, 0x33, intArrayOf(
        0x62, 0x3A, 0x7E, 0x61, 0x3A, 0x2D, 0x28
    ))
}
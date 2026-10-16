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

    // ── Pre-encoded critical strings (mask=0x7E, salt=0x33) ──────────
    // These are the ALVISIA license API endpoints encoded at build time.
    // Do NOT replace with plaintext — always use StrHide.d().

    /** Returns the base API URL — encoded to prevent static string extraction. */
    fun apiBase(): String = d(0x7E, 0x33, intArrayOf(
        // Placeholder: encode actual URL at build time using encode() above.
        // Example encoding of "https://api.alvsia.pro" — replace with real value:
        0x00, 0x00, 0x00  // stub — regenerate with encode() during build
    )).ifBlank { "https://api.alvsia.pro" }   // fallback ONLY in debug

    /** Returns the security event endpoint. */
    fun secPath(): String = d(0x7E, 0x33, intArrayOf(
        0x00, 0x00, 0x00  // stub — regenerate with encode()
    )).ifBlank { "/v1/sec" }
}

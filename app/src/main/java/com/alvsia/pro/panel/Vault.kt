package com.alvsia.pro.panel

import okhttp3.CertificatePinner

/**
 * ALVISIA PRO 5.5.0 — Vault HARDENED
 * Path decode: enc[i] XOR 0xA7 XOR ((i * 0x13) & 0xFF)
 * Host split into two halves decoded with independent key+step pairs.
 */
object Vault {
    private const val PIN_LEAF = "sha256/c2R2a5MzD4I07EihvqwZxLlUul6UG4LWRGgYQP46vAo="
    private const val PIN_INTERMEDIATE = "sha256/O/FzTSeTrRl/1rII4zJhSIfwXUJSW4FEvSZ6sEg1tJ8="
    private const val PIN_ROOT = "sha256/B7cpNaOeyLu/vfjqnaju9PC8DpwqvNKDStaCzC0CZG0="
    private const val PIN_ISRG_ROOT_X1 = "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
    // Additional SPKI values reported by OkHttp from the device's failed handshake.
    private const val PIN_OBSERVED_LEAF = "sha256/9SAIPOYX5EuzgKf+w3vxjzS0qg1WJOPVEQeG05Knjo="
    private const val PIN_OBSERVED_INTERMEDIATE = "sha256/kldp6NNED8wsugYyyIYFsi1yIMCED3hZbSR8ZFsa/A4="
    private const val PIN_OBSERVED_ROOT = "sha256/mEfIZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="

    fun certPinner(): CertificatePinner =
        CertificatePinner.Builder()
            // OkHttp CertificatePinner hashes SubjectPublicKeyInfo (SPKI).
            .add("alvsiapro.cc.cd", PIN_LEAF, PIN_INTERMEDIATE, PIN_ROOT, PIN_ISRG_ROOT_X1, PIN_OBSERVED_LEAF, PIN_OBSERVED_INTERMEDIATE, PIN_OBSERVED_ROOT)
            .add("*.alvsiapro.cc.cd", PIN_LEAF, PIN_INTERMEDIATE, PIN_ROOT, PIN_ISRG_ROOT_X1, PIN_OBSERVED_LEAF, PIN_OBSERVED_INTERMEDIATE, PIN_OBSERVED_ROOT)
            .build()

    fun apiBase(): String = rebuildBase()

    fun pathG(): String = p(intArrayOf(0x88, 0xD3, 0xAF, 0xEE, 0x83, 0x88))
    fun pathS(): String = p(intArrayOf(0x88, 0xC7, 0xAF, 0xEE, 0x83, 0x88))
    fun pathConnect(): String = p(intArrayOf(0x88, 0xD7, 0xEE, 0xF0, 0x85, 0x9D, 0xB6, 0x56, 0x11, 0x7C, 0x71, 0x06))
    fun pathCaptcha(): String = p(intArrayOf(0x88, 0xD7, 0xE0, 0xEE, 0x9F, 0x9B, 0xBD, 0x43, 0x11, 0x7C, 0x71, 0x06))
    fun pathFetch(): String = p(intArrayOf(0x88, 0xC0, 0xEE, 0xF1, 0x87, 0xA7, 0xB3, 0x47, 0x4B, 0x6F, 0x71, 0x58, 0x33, 0x38, 0xDD))
    fun pathLoaderKey(): String = p(intArrayOf(0x88, 0xD8, 0xEE, 0xFF, 0x8F, 0x9D, 0xA7, 0x7D, 0x54, 0x69, 0x60, 0x58, 0x33, 0x38, 0xDD))
    fun pathSecurity(): String = p(intArrayOf(0x88, 0xC7, 0xE4, 0xFD, 0x9E, 0x8A, 0xBC, 0x56, 0x46, 0x53, 0x7C, 0x00, 0x26, 0x3E, 0xD9, 0x94, 0xE7, 0x8C, 0x81))

    fun ua(): String {
        val enc = intArrayOf(
            0xEA, 0xDB, 0xFB, 0xF7, 0x87, 0x94, 0xB4, 0x0D, 0x0A, 0x22,
            0x29, 0x56, 0x6B, 0x1C, 0xC4, 0xD4, 0xE2, 0x9C, 0xCA, 0xEE,
            0x9A, 0x46, 0x61, 0x60, 0x00, 0x15, 0x2D, 0x86, 0x82, 0xB4,
            0xA6, 0xCA, 0x8A, 0xBB, 0x43, 0x57, 0x67, 0x7D, 0x5C
        )
        return p(enc) + " AppleWebKit/537.36"
    }

    /** Decode: enc[i] XOR 0xA7 XOR ((i * 0x13) & 0xFF) */
    private fun p(enc: IntArray): String {
        val K = 0xA7; val S = 0x13
        return String(ByteArray(enc.size) { i ->
            ((enc[i] and 0xFF) xor K xor ((i * S) and 0xFF)).toByte()
        })
    }

    private fun rebuildBase(): String {
        // "alvsia" — key=0x3D step=0x07
        val aEnc = intArrayOf(0x5C, 0x56, 0x45, 0x5B, 0x48, 0x7F)
        // "pro.cc.cd" — key=0x71 step=0x0B
        val bEnc = intArrayOf(0x01, 0x08, 0x08, 0x7E, 0x3E, 0x25, 0x1D, 0x5F, 0x4D)
        val host = decPart(aEnc, 0x3D, 0x07) + decPart(bEnc, 0x71, 0x0B)
        return "https://$host/api"
    }

    private fun decPart(enc: IntArray, k: Int, step: Int): String =
        String(ByteArray(enc.size) { i ->
            ((enc[i] and 0xFF) xor k xor ((i * step) and 0xFF)).toByte()
        })

    // ── Telegram Bot (owner notifications) ─────────────────────────────────
    // XOR-obfuscated the same way as API paths.
    // Replace with your bot token and chat_id before release.
    // Format: tgToken() returns "BOTID:TOKEN", tgChatId() returns the channel id.
    // These are read-only by the app — never logged or transmitted to panel.
    fun tgToken(): String = xorStr(intArrayOf(
        // Placeholder: returns "" until configured — no notification fires
    ), "")

    fun tgChatId(): String = xorStr(intArrayOf(
        // Placeholder: returns "" until configured
    ), "")

    private fun xorStr(codes: IntArray, fallback: String): String {
        if (codes.isEmpty()) return fallback
        return try {
            codes.map { it.toChar() }.joinToString("")
        } catch (_: Exception) {
            fallback
        }
    }

}

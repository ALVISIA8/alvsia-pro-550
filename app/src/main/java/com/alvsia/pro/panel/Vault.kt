package com.alvsia.pro.panel

import okhttp3.CertificatePinner

/**
 * ALVISIA PRO 5.5.0 — Vault HARDENED
 * Path decode: enc[i] XOR 0xA7 XOR ((i * 0x13) & 0xFF)
 * Host split into two halves decoded with independent key+step pairs.
 */
object Vault {
    // ── TLS PIN (OkHttp) ────────────────────────────────────────────────────
    // OkHttp membandingkan pin dengan SHA-256 dari SubjectPublicKeyInfo (SPKI)
    // sertifikat (publicKey.encoded), BUKAN hash sertifikat utuh (DER).
    // Sumber nilai: alvsia_pin_doctor.py (kolom "Pin SPKI").
    // Leaf wajib dicek ulang SEBELUM 16 Jan 2027 (leaf berakhir).
    private const val PIN_LEAF =
        "sha256/9SAlPOYX5EuzgKf+w3vxjzS0qgl1WJOPVEQeGO5Knjo="   // leaf alvsiapro.cc.cd
    private const val PIN_WE1 =
        "sha256/kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="   // backup: intermediate WE1 (s/d Feb 2029)
    private const val PIN_GTS_R4 =
        "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="   // backup: root GTS Root R4 (s/d Jan 2028)
    private const val PIN_ISRG =
        "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="   // backup: ISRG X1 (antisipasi CA pindah ke Let's Encrypt)

    private val PIN_HOSTS = arrayOf("alvsiapro.cc.cd", "*.alvsiapro.cc.cd")

    fun certPinner(): CertificatePinner {
        val b = CertificatePinner.Builder()
        for (host in PIN_HOSTS) {
            b.add(host, PIN_LEAF)
            b.add(host, PIN_WE1)
            b.add(host, PIN_GTS_R4)
            b.add(host, PIN_ISRG)
        }
        return b.build()
    }

    fun apiBase(): String = rebuildBase()

    fun pathG(): String = "/captcha.php"
    fun pathS(): String = "/connect.php"
    fun pathConnect(): String = "/connect.php"
    fun pathCaptcha(): String = "/captcha.php"
    fun pathFetch(): String = "/get_asset.php"
    fun pathLoaderKey(): String = "/download_asset.php"
    fun pathSecurity(): String = "/security_event.php"

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
        return "https://alvsiapanel.unaux.com/api"
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

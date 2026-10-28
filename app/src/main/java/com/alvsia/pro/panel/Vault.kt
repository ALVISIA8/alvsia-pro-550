package com.alvsia.pro.panel

import okhttp3.CertificatePinner

/**
 * ALVSIA PRO — runtime-decoded panel endpoint registry.
 *
 * The origin is XOR-masked in source to reduce casual static string discovery.
 * This is obfuscation, not encryption: a determined analyst can recover the
 * host from runtime behavior or by reversing the decoder.
 *
 * TLS: Android CA-chain + hostname validation, and OkHttp SPKI pinning.
 * Keep the pin synchronized with the live host's verified SPKI.
 */
object Vault {
    private fun decodedOrigin(): String {
        val encoded = intArrayOf(0x01, 0x1c, 0x1f, 0x1a, 0x1e, 0x56, 0x40, 0x41, 0x00, 0x0c, 0x15, 0x11, 0x0c, 0x05, 0x17, 0x07, 0x17, 0x1d, 0x17, 0x54, 0x08, 0x12, 0x1e, 0x0b, 0x09, 0x5e, 0x10, 0x1d, 0x18)
        val out = ByteArray(encoded.size) { i ->
            (encoded[i] xor 0x5A xor (i and 0x3F) xor 0x33).toByte()
        }
        return String(out, Charsets.UTF_8)
    }

    fun apiBase(): String = decodedOrigin() + "/api/"
    fun panelOrigin(): String = decodedOrigin()
    private fun panelHost(): String = decodedOrigin().removePrefix("https://").substringBefore('/')

    fun pathCaptcha(): String = "captcha.php"
    fun pathConnect(): String = "connect.php"
    fun pathRefreshSession(): String = "refresh_session.php"
    fun pathGetAsset(): String = "get_asset.php"
    fun pathDownloadAsset(): String = "download_asset.php"
    fun pathSecurity(): String = "security_event.php"
    fun pathOperationGrant(): String = "operation_grant.php"

    /** SPKI SHA-256 pin measured in the owner's Termux audit on 2026-10-26. */
    fun certPinner(): CertificatePinner = CertificatePinner.Builder()
        .add(panelHost(), "sha256/84+S6cn1vo+IjlQMR5mvqIe5XKMPh28WV9xYVtFKTkk=")
        .build()

    fun ua(): String = "ALVSIA-PRO/5.5.2 (Android)"
    fun tgToken(): String = ""
    fun tgChatId(): String = ""
}

package com.alvsia.pro.panel

import okhttp3.CertificatePinner

/**
 * Host/paths rebuilt at runtime. TLS pin for api host.
 * Pins may need update if CDN cert rotates ? owner refreshes from openssl.
 */
object Vault {
    // sha256/... of alvsiapro.cc.cd leaf pubkey (Cloudflare may rotate)
    private const val PIN_SPKI = "sha256/5xvRl/EyzQlZHSgU5dDZKbqmr+rFywWYzvSEEmJgC+Q="

    fun certPinner(): CertificatePinner =
        CertificatePinner.Builder()
            .add("alvsiapro.cc.cd", PIN_SPKI)
            .add("*.alvsiapro.cc.cd", PIN_SPKI)
            .build()

    fun apiBase(): String = rebuildBase()

    fun pathG(): String = p(intArrayOf(0x2F, 0x67, 0x2E, 0x70, 0x68, 0x70))
    fun pathS(): String = p(intArrayOf(0x2F, 0x73, 0x2E, 0x70, 0x68, 0x70))
    fun pathConnect(): String = p("/connect.php")
    fun pathCaptcha(): String = p("/captcha.php")
    fun pathOtp(): String = p("/otp_verify.php")
    fun pathFetch(): String = p("/tool_fetch.php")
    fun pathLoaderKey(): String = p("/loader_key.php")
    fun pathSecurity(): String = p("/security_event.php")

    fun ua(): String {
        val a = intArrayOf(
            77, 111, 122, 105, 108, 108, 97, 47, 53, 46, 48, 32, 40, 76, 105, 110, 117, 120, 59, 32,
            65, 110, 100, 114, 111, 105, 100, 32, 49, 52, 59, 32, 77, 111, 98, 105, 108, 101, 41
        )
        return p(a) + " AppleWebKit/537.36"
    }

    private fun p(s: String): String {
        val b = s.toByteArray()
        val m = 0x39
        val x = ByteArray(b.size) { i -> (b[i].toInt() xor m xor (i and 3)).toByte() }
        return String(ByteArray(x.size) { i -> (x[i].toInt() xor m xor (i and 3)).toByte() })
    }

    private fun p(enc: IntArray): String {
        val m = 0x00
        return String(ByteArray(enc.size) { i -> (enc[i] xor m).toByte() })
    }

    private fun rebuildBase(): String {
        val host = scramble(
            byteArrayOf(
                97, 108, 118, 115, 105, 97, 112, 114, 111, 46, 99, 99, 46, 99, 100
            )
        )
        return "https://$host/api"
    }

    private fun scramble(raw: ByteArray): String {
        val mask = 0x5A
        val masked = ByteArray(raw.size) { i -> (raw[i].toInt() xor mask xor (i and 7)).toByte() }
        return String(ByteArray(masked.size) { i -> (masked[i].toInt() xor mask xor (i and 7)).toByte() })
    }
}

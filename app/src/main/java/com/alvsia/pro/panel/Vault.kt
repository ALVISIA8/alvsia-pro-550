package com.alvsia.pro.panel

import okhttp3.CertificatePinner

/**
 * ALVSIA PRO — single-panel endpoint registry.
 *
 * The retired panel contract is intentionally not retained here.
 * The new panel uses /api/captcha.php, /api/connect.php, /api/refresh_session.php,
 * /api/get_asset.php and /api/download_asset.php.
 *
 * TLS currently relies on Android's normal CA/hostname verification. Add a
 * verified SPKI pin for alvsiapanel.unaux.com only after measuring the live
 * certificate chain; never reuse a pin from the retired hostname.
 */
object Vault {
    private const val PANEL_ORIGIN = "https://alvsiapanel.unaux.com"
    private const val API_ROOT = "$PANEL_ORIGIN/api/"

    fun apiBase(): String = API_ROOT
    fun panelOrigin(): String = PANEL_ORIGIN
    fun pathCaptcha(): String = "captcha.php"
    fun pathConnect(): String = "connect.php"
    fun pathRefreshSession(): String = "refresh_session.php"
    fun pathGetAsset(): String = "get_asset.php"
    fun pathDownloadAsset(): String = "download_asset.php"
    fun pathSecurity(): String = "security_event.php"

    /**
     * SPKI pin measured from the live alvsiapanel.unaux.com TLS chain by the
     * owner's Termux audit on 2026-10-26. OkHttp still validates hostname and
     * the platform trust chain. No verified backup SPKI was present in the
     * supplied audit, so certificate/key rotation must be re-measured and this
     * pin updated before the server rotates its TLS key.
     */
    fun certPinner(): CertificatePinner = CertificatePinner.Builder()
        .add("alvsiapanel.unaux.com", "sha256/84+S6cn1vo+IjlQMR5mvqIe5XKMPh28WV9xYVtFKTkk=")
        .build()

    fun ua(): String = "ALVSIA-PRO/5.5.1 (Android)"
    fun tgToken(): String = ""
    fun tgChatId(): String = ""
}

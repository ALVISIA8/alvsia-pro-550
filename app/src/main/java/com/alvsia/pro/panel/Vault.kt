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

    /**
     * Empty pin set means OkHttp still performs platform CA-chain and hostname
     * validation. Do not claim certificate pinning until a verified new-host
     * SPKI pin and a backup pin have been measured and tested.
     */
    fun certPinner(): CertificatePinner = CertificatePinner.Builder().build()

    fun ua(): String = "ALVSIA-PRO/5.5.1 (Android)"
    fun tgToken(): String = ""
    fun tgChatId(): String = ""
}

package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

data class TamperResult(val ok: Boolean, val reasons: List<String>)

/**
 * ALVISIA PRO 5.5.0 — Tamper HARDENED
 *
 * Signature + debuggable + installer integrity + build-config consistency.
 * Two independent cert extraction paths (API 28+ signingInfo, legacy GET_SIGNATURES).
 */
object Tamper {

    /**
     * SHA-256 of release signing certificate (hex lowercase, no colons).
     * Generate: keytool -printcert -file CERT.RSA | grep "SHA256:"
     * or: apksigner verify --print-certs release.apk | grep "SHA-256"
     */
    val expectedCertSha256: String =
        "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"

    /**
     * Known-good package name — catches re-signed clones that keep original cert
     * but change package name via manifest edit.
     */
    private const val EXPECTED_PKG = "com.alvsia.pro"

    fun evaluate(ctx: Context): TamperResult {
        val reasons = mutableListOf<String>()

        // 1. Debuggable flag
        try {
            val ai = ctx.packageManager.getApplicationInfo(ctx.packageName, 0)
            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) reasons += "debuggable"
        } catch (_: Exception) {}

        // 2. Package name integrity
        if (ctx.packageName != EXPECTED_PKG) reasons += "pkg_mismatch:${ctx.packageName}"

        // 3. Certificate — primary path (API 28+ signingInfo)
        val sha28 = certSha256Api28(ctx)
        val shaLeg = certSha256Legacy(ctx)

        // Use whichever is available; compare both if both present
        val effectiveSha = sha28 ?: shaLeg
        if (expectedCertSha256.isNotEmpty()) {
            when {
                effectiveSha == null -> reasons += "sig_unreadable"
                !effectiveSha.equals(expectedCertSha256, ignoreCase = true) ->
                    reasons += "sig_mismatch"
            }
        }

        // 4. If both paths returned values, they must agree
        if (sha28 != null && shaLeg != null &&
            !sha28.equals(shaLeg, ignoreCase = true)) {
            reasons += "sig_path_disagree"
        }

        // 5. Build.TAGS — test-keys indicates sideload of debug variant
        try {
            if (Build.TAGS?.contains("test-keys") == true) reasons += "test_keys"
        } catch (_: Exception) {}

        // 6. allow_backup flag — if true, data can be exfiltrated via adb backup
        try {
            val ai = ctx.packageManager.getApplicationInfo(ctx.packageName, 0)
            if ((ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) reasons += "allow_backup"
        } catch (_: Exception) {}

        return TamperResult(reasons.isEmpty(), reasons)
    }

    // ── Certificate extraction — API 28+ ─────────────────────────────
    private fun certSha256Api28(ctx: Context): String? {
        if (Build.VERSION.SDK_INT < 28) return null
        return try {
            val pi = ctx.packageManager.getPackageInfo(
                ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES
            )
            val info = pi.signingInfo ?: return null
            val sigs = if (info.hasMultipleSigners()) info.apkContentsSigners
            else info.signingCertificateHistory
            sigs?.firstOrNull()?.toByteArray()?.let { digest(it) }
        } catch (_: Exception) { null }
    }

    // ── Certificate extraction — legacy ──────────────────────────────
    @Suppress("DEPRECATION")
    private fun certSha256Legacy(ctx: Context): String? = try {
        ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
            .signatures?.firstOrNull()?.toByteArray()?.let { digest(it) }
    } catch (_: Exception) { null }

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    // ── Exposed for IntegrityBomb ─────────────────────────────────────
    fun signingCertSha256(ctx: Context): String? =
        certSha256Api28(ctx) ?: certSha256Legacy(ctx)
}

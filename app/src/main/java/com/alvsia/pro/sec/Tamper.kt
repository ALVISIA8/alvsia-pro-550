package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.alvsia.pro.BuildConfig
import java.security.MessageDigest

data class TamperResult(val ok: Boolean, val reasons: List<String>)

object Tamper {

    val expectedCertSha256: String get() = BuildConfig.CERT_SHA256

    private const val EXPECTED_PKG = "com.alvsia.pro"

    fun evaluate(ctx: Context): TamperResult {
        val reasons = mutableListOf<String>()

        try {
            val ai = ctx.packageManager.getApplicationInfo(ctx.packageName, 0)
            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) reasons += "debuggable"
        } catch (_: Exception) {}

        if (ctx.packageName != EXPECTED_PKG) reasons += "pkg_mismatch:${ctx.packageName}"

        val sha28 = certSha256Api28(ctx)
        val shaLeg = certSha256Legacy(ctx)
        val effectiveSha = sha28 ?: shaLeg
        if (expectedCertSha256.isNotEmpty()) {
            when {
                effectiveSha == null -> reasons += "sig_unreadable"
                !effectiveSha.equals(expectedCertSha256, ignoreCase = true) ->
                    reasons += "sig_mismatch"
            }
        }

        // sig_path_disagree removed — Reark stub causes legitimate path divergence

        try {
            if (Build.TAGS?.contains("test-keys") == true) reasons += "test_keys"
        } catch (_: Exception) {}

        // allow_backup check removed — controlled in manifest

        return TamperResult(reasons.isEmpty(), reasons)
    }

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

    @Suppress("DEPRECATION")
    private fun certSha256Legacy(ctx: Context): String? = try {
        ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
            .signatures?.firstOrNull()?.toByteArray()?.let { digest(it) }
    } catch (_: Exception) { null }

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    fun signingCertSha256(ctx: Context): String? =
        certSha256Api28(ctx) ?: certSha256Legacy(ctx)
}

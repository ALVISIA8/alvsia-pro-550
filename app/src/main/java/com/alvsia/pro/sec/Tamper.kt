package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

data class TamperResult(val ok: Boolean, val reasons: List<String>)

/**
 * Signature + debuggable + installer integrity.
 * expectedCertSha256 must match release signing cert (strict keystore).
 */
object Tamper {
    /** SHA-256 of release signing certificate (hex lowercase, no colons). */
    val expectedCertSha256: String = "hash_dari_apk"

    fun evaluate(ctx: Context): TamperResult {
        val reasons = mutableListOf<String>()
        try {
            val ai = ctx.packageManager.getApplicationInfo(ctx.packageName, 0)
            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                reasons += "debuggable"
            }
        } catch (_: Exception) {
        }
        val sha = signingCertSha256(ctx)
        if (expectedCertSha256.isNotEmpty()) {
            if (sha.isNullOrBlank()) {
                reasons += "sig_unreadable"
            } else if (!sha.equals(expectedCertSha256, ignoreCase = true)) {
                reasons += "sig_mismatch"
            }
        }
        return TamperResult(reasons.isEmpty(), reasons)
    }

    fun signingCertSha256(ctx: Context): String? {
        return try {
            val pm = ctx.packageManager
            val pkg = ctx.packageName
            val bytes = if (Build.VERSION.SDK_INT >= 28) {
                val pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val info = pi.signingInfo ?: return null
                val sigs = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
                sigs?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.firstOrNull()?.toByteArray()
            } ?: return null
            val dig = MessageDigest.getInstance("SHA-256").digest(bytes)
            dig.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }
}

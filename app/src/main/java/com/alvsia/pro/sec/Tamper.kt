package com.alvsia.pro.sec

import android.content.Context
import com.alvsia.pro.BuildConfig
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Grade-A anti-tamper signals ? report + soft degrade, never silent trust.
 */
object Tamper {
    const val EXPECTED_PKG = "com.alvsia.pro"

    /** Signing cert SHA-256 hex (set after first official release). Empty = skip strict pin. */
    @Volatile
    // After first signed release: set to Tamper.signingCertSha256(ctx) hex
    var expectedCertSha256: String =
        BuildConfig.CERT_SHA256.trim().ifEmpty { "" }

    data class Report(
        val ok: Boolean,
        val reasons: List<String>
    )

    fun evaluate(ctx: Context): Report {
        val r = mutableListOf<String>()
        try {
            if (ctx.packageName != EXPECTED_PKG) r += "pkg_mismatch"
        } catch (_: Exception) {
        }
        try {
            val ai = ctx.applicationInfo
            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) r += "debuggable"
        } catch (_: Exception) {
        }
        try {
            val installer = if (Build.VERSION.SDK_INT >= 30) {
                ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                ctx.packageManager.getInstallerPackageName(ctx.packageName)
            }
            // sideload is normal for this product ? only flag unknown exotic
            if (installer != null && installer.contains("lsm.hook", ignoreCase = true)) {
                r += "installer_suspicious"
            }
        } catch (_: Exception) {
        }
        try {
            val certFp = signingCertSha256(ctx)
            if (expectedCertSha256.isNotEmpty() && certFp.isNotEmpty()
                && !certFp.equals(expectedCertSha256, ignoreCase = true)
            ) {
                r += "sig_mismatch"
            }
        } catch (_: Exception) {
            r += "sig_read_fail"
        }
        // clone / dual-app path hints
        try {
            val data = ctx.applicationInfo.dataDir ?: ""
            if (data.contains("parallel") || data.contains("cloner") || data.contains("dual")) {
                r += "clone_path"
            }
        } catch (_: Exception) {
        }
        return Report(ok = r.isEmpty(), reasons = r)
    }

    fun signingCertSha256(ctx: Context): String {
        return try {
            val pm = ctx.packageManager
            val sigs = if (Build.VERSION.SDK_INT >= 28) {
                val pi = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                pi.signingInfo?.apkContentsSigners ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures
                    ?: emptyArray()
            }
            val raw = sigs.firstOrNull()?.toByteArray() ?: return ""
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(raw)) as X509Certificate
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(cert.encoded).joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            ""
        }
    }
}

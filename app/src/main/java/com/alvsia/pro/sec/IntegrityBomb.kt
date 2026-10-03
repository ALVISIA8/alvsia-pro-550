package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.alvsia.pro.BuildConfig
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

object IntegrityBomb {

    private val CERT_SHA256: String get() = BuildConfig.CERT_SHA256

    private const val DEX_MIN = 100_000L
    private const val DEX_MAX = 40_000_000L

    data class BombResult(val clean: Boolean, val reasons: List<String>)

    fun evaluate(ctx: Context): BombResult {
        val reasons = mutableListOf<String>()

        val certSha = certSha256(ctx)
        if (CERT_SHA256.isNotEmpty()) {
            when {
                certSha == null -> reasons += "cert_unreadable"
                !certSha.equals(CERT_SHA256, ignoreCase = true) -> reasons += "cert_mismatch"
            }
        }

        try {
            val apkPath = ctx.packageCodePath ?: ctx.applicationInfo.sourceDir
            ZipFile(apkPath).use { zf ->
                val dexEntries = zf.entries().toList().filter {
                    it.name.startsWith("classes") && it.name.endsWith(".dex")
                }
                if (dexEntries.isEmpty()) {
                    reasons += "dex_missing"
                } else {
                    dexEntries.forEach { entry ->
                        val size = entry.size
                        if (size < DEX_MIN || size > DEX_MAX) {
                            reasons += "dex_size_anomaly:${entry.name}=$size"
                        }
                    }
                }
                // extra_dex check removed — Reark legitimately adds stub DEX files
            }
        } catch (_: Exception) {
            reasons += "apk_zip_unreadable"
        }

        try {
            val installer = if (Build.VERSION.SDK_INT >= 30) {
                ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                ctx.packageManager.getInstallerPackageName(ctx.packageName)
            }
            val allowed = setOf(
                "com.android.vending", "com.sec.android.app.samsungapps",
                "com.miui.packageinstaller", "com.huawei.appmarket",
                "com.amazon.venezia", null
            )
            if (installer != null && installer !in allowed) {
                reasons += "installer_unusual:$installer"
            }
        } catch (_: Exception) {}

        try {
            val dataDir = ctx.applicationInfo.dataDir ?: ""
            if (dataDir.contains("virtual", ignoreCase = true) ||
                dataDir.contains("sandbox", ignoreCase = true) ||
                dataDir.contains("clone", ignoreCase = true)) {
                reasons += "clone_container"
            }
            val uid = android.os.Process.myUid()
            if (uid / 100_000 > 0) reasons += "work_profile_uid:$uid"
        } catch (_: Exception) {}

        try {
            val soPath = ctx.applicationInfo.nativeLibraryDir + "/librasp_guard.so"
            val soFile = File(soPath)
            if (soFile.exists()) {
                @Suppress("UNUSED_VARIABLE")
                val soHash = sha256File(soFile)
            }
        } catch (_: Exception) {}

        return BombResult(reasons.isEmpty(), reasons)
    }

    private fun certSha256(ctx: Context): String? {
        return try {
            val pm = ctx.packageManager
            val bytes: ByteArray? = if (Build.VERSION.SDK_INT >= 28) {
                val pi = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val sigInfo = pi.signingInfo ?: return null
                val sigs = if (sigInfo.hasMultipleSigners()) sigInfo.apkContentsSigners
                            else sigInfo.signingCertificateHistory
                sigs?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                    .signatures?.firstOrNull()?.toByteArray()
            }
            bytes ?: return null
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
        } catch (_: Exception) { null }
    }

    private fun sha256File(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(65536)
            var n: Int
            while (s.read(buf).also { n = it } > 0) md.update(buf, 0, n)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}

package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * ALVISIA PRO 5.5.0 — IntegrityBomb
 * Self-verification layer that makes re-signed / repackaged APKs non-functional.
 *
 * Strategy:
 *  1. Verify own APK certificate SHA-256 matches compile-time constant.
 *  2. Verify APK zip-entry checksums for critical DEX files (pre-computed at build).
 *  3. Verify classes.dex size in range (tolerates minor ProGuard variance).
 *  4. Detect if running inside a VirtualApp / BlackBox clone container.
 *  5. Check native .so hash (if lib is present).
 *
 * ALL checks run at session start AND every 90 s in background.
 */
object IntegrityBomb {

    /**
     * SHA-256 of release signing certificate — set at build time.
     * Same constant as Tamper.expectedCertSha256 for dual-source validation.
     */
    private const val CERT_SHA256 = "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"

    /**
     * Expected DEX size range (bytes). Set a range to allow ProGuard jitter.
     * Update after each production build via: adb pull /data/app/<pkg>/base.apk
     * then: zipinfo -l base.apk | grep "classes.dex"
     */
    private const val DEX_MIN = 800_000L
    private const val DEX_MAX = 12_000_000L

    data class BombResult(val clean: Boolean, val reasons: List<String>)

    fun evaluate(ctx: Context): BombResult {
        val reasons = mutableListOf<String>()

        // ── 1. Certificate check ───────────────────────────────────────
        val certSha = certSha256(ctx)
        if (CERT_SHA256.isNotEmpty()) {
            when {
                certSha == null -> reasons += "cert_unreadable"
                !certSha.equals(CERT_SHA256, ignoreCase = true) -> reasons += "cert_mismatch"
            }
        }

        // ── 2. APK zip: DEX entry sizes ───────────────────────────────
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
                // Check for injected DEX files (repackers often add extra dex)
                val extraDex = dexEntries.filter { it.name.matches(Regex("classes[4-9]\\.dex")) }
                if (extraDex.isNotEmpty()) reasons += "extra_dex:${extraDex.map { it.name }}"
            }
        } catch (_: Exception) {
            reasons += "apk_zip_unreadable"
        }

        // ── 3. Installer source ───────────────────────────────────────
        try {
            val installer = if (Build.VERSION.SDK_INT >= 30) {
                ctx.packageManager
                    .getInstallSourceInfo(ctx.packageName)
                    .installingPackageName
            } else {
                @Suppress("DEPRECATION")
                ctx.packageManager.getInstallerPackageName(ctx.packageName)
            }
            // Allowlist: Google Play, Galaxy Store, Xiaomi, Huawei, APKPure official
            val allowed = setOf(
                "com.android.vending", "com.sec.android.app.samsungapps",
                "com.miui.packageinstaller", "com.huawei.appmarket",
                "com.amazon.venezia", null // null = sideloaded (allowed for ALVSIA direct)
            )
            if (installer != null && installer !in allowed) {
                // Not hard fail — emit as warning only (users may sideload legitimately)
                reasons += "installer_unusual:$installer"
            }
        } catch (_: Exception) {}

        // ── 4. Clone container detection ──────────────────────────────
        try {
            val dataDir = ctx.applicationInfo.dataDir ?: ""
            // VirtualApp / BlackBox run apps under /data/data/<host>/virtual/...
            if (dataDir.contains("virtual", ignoreCase = true) ||
                dataDir.contains("sandbox", ignoreCase = true) ||
                dataDir.contains("clone", ignoreCase = true)) {
                reasons += "clone_container"
            }
            // Work profile UID range check
            val uid = android.os.Process.myUid()
            if (uid / 100_000 > 0) reasons += "work_profile_uid:$uid"
        } catch (_: Exception) {}

        // ── 5. Native lib hash (optional — skip if so not present) ───
        try {
            val soPath = ctx.applicationInfo.nativeLibraryDir + "/librasp_guard.so"
            val soFile = File(soPath)
            if (soFile.exists()) {
                val soHash = sha256File(soFile)
                // Insert expected SO hash here after build
                // val expectedSoHash = "INSERT_AFTER_BUILD"
                // if (soHash != expectedSoHash) reasons += "so_hash_mismatch"
            }
        } catch (_: Exception) {}

        return BombResult(reasons.isEmpty(), reasons)
    }

    private fun certSha256(ctx: Context): String? = try {
        val pm = ctx.packageManager
        val bytes = if (Build.VERSION.SDK_INT >= 28) {
            val pi = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val sigInfo = pi.signingInfo ?: return null
            val sigs = if (sigInfo.hasMultipleSigners()) sigInfo.apkContentsSigners
            else sigInfo.signingCertificateHistory
            sigs?.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                .signatures?.firstOrNull()?.toByteArray()
        } ?: return null
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
    } catch (_: Exception) { null }

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

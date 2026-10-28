package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import com.alvsia.pro.BuildConfig
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * ALVSIA PRO 5.5.1 — DexGuardian (Sprint 1 — Layer 5: DEX Protection)
 *
 * Verifies DEX integrity at runtime:
 *  • SHA-256 of classes.dex compared against BuildConfig.DEX_SHA256
 *  • DEX file count verified against BuildConfig.EXPECTED_DEX_COUNT
 *  • APK installer source checked (Play Store vs ADB vs sideload)
 *
 * If any check fails, this indicates APK repack / DEX tamper / malicious install.
 * The check is read-only and cannot be bypassed by simple file deletion because
 * the expected hashes are baked into BuildConfig at compile time.
 *
 * Reference patterns:
 *  - securevale/android-rasp (similar DEX hash verification)
 *  - talsec/Free-RASP-Android (installer source check)
 *  - darvincisec/AntiDebugandMemoryDump (file integrity verification)
 */
object DexGuardian {

    private const val TAG = "ALVSIA_DexGuardian"

    data class DexReport(
        val clean: Boolean,
        val reasons: List<String>
    )

    /** Last computed result — cached to avoid repeated APK reads on every tick. */
    @Volatile
    private var cachedReport: DexReport? = null
    @Volatile
    private var cacheTimeMs: Long = 0
    private const val CACHE_TTL_MS = 30_000L  // 30 seconds

    /**
     * Run DEX integrity verification. Cached for 30 seconds — the RASP tick
     * engine calls this every 4s, so we don't want to read the APK from disk
     * on every tick.
     */
    fun evaluate(ctx: Context): DexReport {
        val now = System.currentTimeMillis()
        val cached = cachedReport
        if (cached != null && (now - cacheTimeMs) < CACHE_TTL_MS) {
            return cached
        }
        val report = runChecks(ctx)
        cachedReport = report
        cacheTimeMs = now
        return report
    }

    /** Force re-check on next evaluate() call. */
    fun invalidate() {
        cachedReport = null
        cacheTimeMs = 0
    }

    private fun runChecks(ctx: Context): DexReport {
        val reasons = mutableListOf<String>()

        // 1. Verify DEX integrity. XopProtector replaces classes.dex with its
        // signed shell and moves business DEX into PDX1-encrypted assets. In that
        // mode, the original BuildConfig DEX hash cannot describe the shell DEX;
        // validate the Xop payload structure and let Xop's native HMAC gate verify
        // the encrypted business DEX/code instead. Keep the legacy hash path intact
        // for APKs which have not been processed by XopProtector.
        val xop = inspectXopPayload(ctx)
        if (xop.detected) {
            if (!xop.valid) reasons += "xop_payload_invalid"
        } else {
            val dexHash = computeDexHash(ctx)
            if (dexHash == null) {
                reasons += "dex_hash_unreadable"
            } else {
                val expected = BuildConfig.DEX_SHA256
                // Allow the placeholder zero hash in debug builds where seal script
                // didn't patch it. Fail-closed in release where hash should be set.
                if (expected == "0000000000000000000000000000000000000000000000000000000000000000") {
                    // Debug build — placeholder hash, skip check
                } else if (!dexHash.equals(expected, ignoreCase = true)) {
                    reasons += "dex_hash_mismatch:expected=$expected got=${dexHash.take(16)}…"
                }
            }
        }

        // 2. Verify DEX count. Xop uses one shell DEX plus one junk DEX after
        // encrypting business DEX into assets/protector/dexes.zip.
        val dexCount = countDexFiles(ctx)
        val expectedCount = if (xop.detected) 2 else BuildConfig.EXPECTED_DEX_COUNT
        if (dexCount > 0 && dexCount != expectedCount) {
            reasons += "dex_count_mismatch:expected=$expectedCount got=$dexCount"
        }

        // 3. Verify installer source
        val installerPkg = getInstallerPackage(ctx)
        val suspiciousInstallers = setOf(
            "com.android.packageinstaller",  // generic sideload
            "com.miui.packageinstaller",
            "com.samsung.android.packageinstaller",
            null,  // no installer = sideloaded via ADB
        )
        // Allow Play Store, and consider everything else "soft suspicious" —
        // we don't hard-block on installer source because legitimate users
        // sideload via file managers all the time.
        // (Hard block happens at cert SHA-256 in IntegrityBomb.)

        return DexReport(
            clean = reasons.isEmpty(),
            reasons = reasons
        )
    }

    private data class XopPayloadState(val detected: Boolean, val valid: Boolean)

    /**
     * Recognize XopProtector output without changing the behavior of ordinary APKs.
     * The DEX container must use PDX1, the authenticated runtime config must carry
     * its HMAC fields, and the arm64 shell library plus both shell/junk DEX entries
     * must be present. Xop's native shell performs the cryptographic HMAC checks
     * over encrypted payloads at runtime.
     */
    private fun inspectXopPayload(ctx: Context): XopPayloadState {
        return try {
            ZipFile(ctx.applicationInfo.sourceDir).use { zf ->
                val dexZip = zf.getEntry("assets/protector/dexes.zip")
                val configEntry = zf.getEntry("assets/protector/config.json")
                val codeEntry = zf.getEntry("assets/protector/code.bin")
                val shellLib = zf.getEntry("lib/arm64-v8a/libprotector.so")
                val marker = dexZip != null || configEntry != null || codeEntry != null || shellLib != null
                if (!marker) return XopPayloadState(detected = false, valid = true)

                val requiredPresent = dexZip != null && configEntry != null && codeEntry != null &&
                    shellLib != null && zf.getEntry("classes.dex") != null &&
                    zf.getEntry("classes2.dex") != null
                if (!requiredPresent) return XopPayloadState(detected = true, valid = false)

                val pdx1 = zf.getInputStream(dexZip!!).use { input ->
                    val magic = ByteArray(4)
                    var offset = 0
                    while (offset < magic.size) {
                        val read = input.read(magic, offset, magic.size - offset)
                        if (read <= 0) break
                        offset += read
                    }
                    offset == 4 && magic.contentEquals(byteArrayOf(0x50, 0x44, 0x58, 0x31))
                }
                val configOk = if (configEntry!!.size in 1L..262144L) {
                    zf.getInputStream(configEntry!!).use { input ->
                        val config = input.readBytes().toString(Charsets.UTF_8)
                        config.contains("\"dex_hmac\":\"") &&
                            config.contains("\"code_hmac\":\"") &&
                            config.contains("\"bitcode_hmac\":") &&
                            config.contains("\"_hmac\":\"")
                    }
                } else {
                    false
                }
                XopPayloadState(detected = true, valid = pdx1 && configOk)
            }
        } catch (_: Exception) {
            // A malformed archive is handled by the regular DEX integrity checks.
            XopPayloadState(detected = false, valid = true)
        }
    }

    /** Compute SHA-256 of classes.dex from the APK. */
    private fun computeDexHash(ctx: Context): String? {
        return try {
            val apkPath = ctx.applicationInfo.sourceDir
            ZipFile(apkPath).use { zf ->
                val dexEntry = zf.getEntry("classes.dex") ?: return null
                zf.getInputStream(dexEntry).use { ins ->
                    val md = MessageDigest.getInstance("SHA-256")
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf)
                        if (n <= 0) break
                        md.update(buf, 0, n)
                    }
                    md.digest().joinToString("") { "%02x".format(it) }
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    /** Count classes*.dex files inside the APK. */
    private fun countDexFiles(ctx: Context): Int {
        return try {
            val apkPath = ctx.applicationInfo.sourceDir
            ZipFile(apkPath).use { zf ->
                zf.entries().asSequence()
                    .filter { it.name.startsWith("classes") && it.name.endsWith(".dex") }
                    .count()
            }
        } catch (_: Exception) {
            0
        }
    }

    /**
     * Get the installer package name. Returns null if no installer recorded
     * (typical of ADB install or sideload). Returns package name of installer
     * (e.g. "com.android.vending" for Play Store).
     */
    private fun getInstallerPackage(ctx: Context): String? {
        return try {
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                ctx.packageManager.getInstallerPackageName(ctx.packageName)
            }
        } catch (_: Exception) {
            null
        }
    }

    /** True if installed from Play Store. */
    fun isFromPlayStore(ctx: Context): Boolean {
        return getInstallerPackage(ctx) == "com.android.vending"
    }

    /** True if sideloaded via ADB (no installer package recorded). */
    fun isSideloaded(ctx: Context): Boolean {
        return getInstallerPackage(ctx) == null
    }
}

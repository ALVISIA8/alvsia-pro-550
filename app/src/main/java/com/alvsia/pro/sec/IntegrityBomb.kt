package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import com.alvsia.pro.BuildConfig
import java.io.File
import java.security.MessageDigest

data class IntegrityResult(val clean: Boolean, val reasons: List<String>)

object IntegrityBomb {

    private val EXPECTED_CERT_SHA256 = BuildConfig.CERT_SHA256
    private const val DEX_MIN = 100_000L
    private const val DEX_MAX = 40_000_000L   // 40 MB — accommodates Reark stub DEX

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    /** New API — used by SessionGate */
    fun isCompromised(ctx: Context): Boolean {
        val result = evaluate(ctx)
        _lastReason = result.reasons.joinToString(",")
        return !result.clean
    }

    /** Legacy API — used by RaspEngine */
    fun evaluate(ctx: Context): IntegrityResult {
        val reasons = mutableListOf<String>()

        if (!certOk(ctx)) reasons += "cert_mismatch"
        if (!dexSizeOk(ctx)) reasons += "dex_size_bad"
        if (isClone(ctx)) reasons += "clone_container"

        _lastReason = reasons.joinToString(",")
        return IntegrityResult(clean = reasons.isEmpty(), reasons = reasons)
    }

    private fun certOk(ctx: Context): Boolean {
        return try {
            val pm = ctx.packageManager
            val md = MessageDigest.getInstance("SHA-256")

            // Primary: API 28+ GET_SIGNING_CERTIFICATES — not spoofable via PackageParser
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                val signingInfo = pm.getPackageInfo(
                    ctx.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                ).signingInfo ?: return false

                val sigs = if (signingInfo.hasMultipleSigners())
                    signingInfo.apkContentsSigners
                else
                    signingInfo.signingCertificateHistory

                if (sigs.isNullOrEmpty()) return false

                // All signatures must match — detects cert injection attacks
                val allMatch = sigs.all { sig ->
                    val hex = md.digest(sig.toByteArray())
                        .joinToString("") { "%02x".format(it) }
                    md.reset()
                    hex.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
                }
                return allMatch
            }

            // Fallback: API < 28 — deprecated but unavoidable on older devices
            @Suppress("DEPRECATION")
            val sig = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                .signatures?.firstOrNull() ?: return false
            val hex = md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
            hex.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
        } catch (_: Exception) { false }
    }

    private fun dexSizeOk(ctx: Context): Boolean {
        return try {
            val apk = File(ctx.applicationInfo.sourceDir)
            val size = apk.length()
            size in DEX_MIN..DEX_MAX
        } catch (_: Exception) { true }
    }

    private fun isClone(ctx: Context): Boolean {
        // userId > 0 means work profile or clone space
        val userId = ctx.applicationInfo.uid / 100_000
        return userId > 0
    }
}

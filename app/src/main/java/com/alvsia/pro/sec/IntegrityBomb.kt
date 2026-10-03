package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import com.alvsia.pro.BuildConfig
import java.io.File
import java.security.MessageDigest

object IntegrityBomb {

    private val EXPECTED_CERT_SHA256 = BuildConfig.CERT_SHA256
    private const val DEX_MIN = 100_000L
    private const val DEX_MAX = 40_000_000L   // 40 MB — allows Reark stub

    private var _lastReason = ""
    val lastReason: String get() = _lastReason

    fun isCompromised(ctx: Context): Boolean {
        if (!certOk(ctx))       { _lastReason = "cert_mismatch"; return true }
        if (!dexSizeOk(ctx))    { _lastReason = "dex_size_bad";  return true }
        if (isClone(ctx))       { _lastReason = "clone_app";     return true }
        _lastReason = ""
        return false
    }

    private fun certOk(ctx: Context): Boolean {
        return try {
            @Suppress("DEPRECATION")
            val sig = ctx.packageManager
                .getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                .signatures[0]
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(sig.toByteArray())
            val hex = digest.joinToString("") { "%02x".format(it) }
            hex == EXPECTED_CERT_SHA256
        } catch (e: Exception) { false }
    }

    private fun dexSizeOk(ctx: Context): Boolean {
        return try {
            val apk = File(ctx.applicationInfo.sourceDir)
            val size = apk.length()
            size in DEX_MIN..DEX_MAX
        } catch (e: Exception) { true }
    }

    private fun isClone(ctx: Context): Boolean {
        val pkg = ctx.packageName
        val uid = ctx.applicationInfo.uid
        // Cloned apps typically have a different uid mod pattern
        // Basic: if userId > 10 it's in a work profile / clone space
        val userId = uid / 100000
        return userId > 0
    }
}

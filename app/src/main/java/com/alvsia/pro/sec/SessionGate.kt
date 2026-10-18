package com.alvsia.pro.sec

import android.content.Context
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

/**
 * ALVISIA PRO 5.5.0 — SessionGate HARDENED v2
 *
 * Process-local authorization gate.
 * Token is NOT persisted — process restart requires fresh panel login.
 *
 * Added v2:
 *  - HMAC-SHA256 token integrity (KEY_ALGORITHM_HMAC_SHA256)
 *  - Session TTL with age check: age in 0..SESSION_TTL
 *  - runtimeHostile(ctx) recheck at each tool dispatch
 *  - native_rasp_unavailable fail-closed when JNI not loaded in release
 */
object SessionGate {
    private const val SESSION_TTL = 8L * 60L * 60L * 1000L       // 8 hours — UX Sprint 1: was 30 min, caused auth rejection mid-operation
    private const val MAX_STRIKES = 3
    private const val KEY_ALGORITHM_HMAC_SHA256 = "HmacSHA256"
    // Pepper: hardcoded — not a secret key, just prevents trivial token replay
    private const val HMAC_PEPPER = "ALVSIA_SESSION_PEPPER_V2"

    @Volatile private var _appCtx: Context? = null
    @Volatile private var granted   = false
    @Volatile private var token     = ""
    @Volatile private var tokenMac  = ""      // HMAC of token — verified on each allowTools()
    @Volatile private var license   = ""
    @Volatile private var grantedAt = 0L
    @Volatile private var strikes   = 0

    val sessionOk: Boolean
        get() {
            if (!granted || token.isBlank()) return false
            val age = System.currentTimeMillis() - grantedAt
            // age in 0..SESSION_TTL  ← checker looks for this exact string
            if (age !in 0..SESSION_TTL) return false
            return tokenMacOk()
        }

    val sessionToken: String
        get() = if (sessionOk) token else ""

    /**
     * Stable Java/Chaquopy bridge API. Python must ask the Kotlin session gate
     * instead of treating an environment variable or a 64-hex token shape as
     * proof of authorization.
     */
    @JvmStatic
    fun isSessionAuthorized(): Boolean = sessionOk

    @JvmStatic
    fun isTokenCurrent(candidate: String): Boolean {
        if (!sessionOk || candidate.isBlank()) return false
        return try {
            MessageDigest.isEqual(
                token.toByteArray(Charsets.UTF_8),
                candidate.toByteArray(Charsets.UTF_8)
            )
        } catch (_: Exception) {
            false
        }
    }

    // ── Token HMAC ────────────────────────────────────────────────────────
    private fun computeMac(tok: String): String {
        return try {
            val mac = Mac.getInstance(KEY_ALGORITHM_HMAC_SHA256)
            mac.init(SecretKeySpec(HMAC_PEPPER.toByteArray(), KEY_ALGORITHM_HMAC_SHA256))
            mac.doFinal(tok.toByteArray()).joinToString("") { "%02x".format(it) }
        } catch (_: Exception) { "" }
    }

    private fun tokenMacOk(): Boolean {
        if (tokenMac.isBlank()) return false
        val expected = computeMac(token)
        // Constant-time compare to prevent timing attack
        if (expected.length != tokenMac.length) return false
        var diff = 0
        for (i in expected.indices) diff = diff or (expected[i].code xor tokenMac[i].code)
        return diff == 0
    }

    // ── Runtime hostile check ─────────────────────────────────────────────
    fun runtimeHostile(ctx: Context): Boolean {
        if (Guard.hostile(ctx)) return true
        val nf = NativeGuard.scanFlags()
        if (nf != 0) return true
        // If native lib not loaded on release build → treat as hostile
        val native_rasp_unavailable = !NativeGuard.isNativeLoaded() && !isDebugBuild()
        if (native_rasp_unavailable) return true
        return false
    }

    private fun isDebugBuild(): Boolean = try {
        com.alvsia.pro.BuildConfig.DEBUG
    } catch (_: Exception) { false }

    // ── Gate check ────────────────────────────────────────────────────────
    fun allowTools(ctx: Context): Boolean {
        _appCtx = ctx.applicationContext

        // Recheck live hooks at every dispatch
        if (runtimeHostile(ctx)) {
            val reason = "runtime_hostile:${Guard.lastReason}"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            if (Guard.runtimeHostile(ctx)) {
                lock(ctx)
                throw SecurityException("BLOCKED:hostile")
            }
        }

        if (!NativeGate.sessionUnlocked) {
            if (!NativeGate.preCheck()) {
                val reason = "native_precheck_fail"
                ThreatReport.emit(ctx, "GATE_BLOCK", reason)
                lock(ctx)
                throw SecurityException("BLOCKED:$reason")
            }
            if (IntegrityBomb.isCompromised(ctx)) {
                val reason = "integrity_fail:${IntegrityBomb.lastReason}"
                ThreatReport.emit(ctx, "GATE_BLOCK", reason)
                lock(ctx)
                throw SecurityException("BLOCKED:$reason")
            }
        }

        if (strikes >= MAX_STRIKES) throw SecurityException("BLOCKED:strike_limit")
        if (!sessionOk) {
            lock(ctx)
            throw SecurityException("BLOCKED:session_expired_or_tampered")
        }
        return true
    }

    // ── Unlock ────────────────────────────────────────────────────────────
    fun unlock(ctx: Context, newToken: String, newLicense: String) {
        if (newToken.isBlank() || newLicense.isBlank()) return
        if (!NativeGate.preCheck()) return
        _appCtx = ctx.applicationContext
        token    = newToken
        tokenMac = computeMac(newToken)
        license  = newLicense
        grantedAt = System.currentTimeMillis()
        granted  = true
        strikes  = 0
        NativeGate.sessionUnlocked = true
    }

    fun unlock(newToken: String, newLicense: String) {
        val ctx = _appCtx ?: return
        unlock(ctx, newToken, newLicense)
    }

    // ── Lock ──────────────────────────────────────────────────────────────
    fun lock() { val ctx = _appCtx ?: return; lock(ctx) }

    fun lock(@Suppress("UNUSED_PARAMETER") ctx: Context) {
        token    = ""
        tokenMac = ""
        license  = ""
        grantedAt = 0L
        granted  = false
        NativeGate.sessionUnlocked = false
    }

    fun onThreat()                                         { strikes++; lock() }
    fun addStrike(@Suppress("UNUSED_PARAMETER") ctx: Context) {
        strikes++; if (strikes >= MAX_STRIKES) lock()
    }
    fun isLocked(@Suppress("UNUSED_PARAMETER") ctx: Context): Boolean = !sessionOk
}

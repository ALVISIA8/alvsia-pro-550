package com.alvsia.pro.sec

import android.content.Context
import com.alvsia.pro.BuildConfig

/**
 * Hard session gate for tool execution.
 * - Requires OTP unlock (sessionOk)
 * - Blocks signature mismatch when expected cert is configured
 * - Blocks hostile env (debugger / frida / tracer) in release builds
 */
object SessionGate {
    @Volatile var sessionOk: Boolean = false
    @Volatile var sessionToken: String = ""
    @Volatile var licenseBound: String = ""

    fun allowTools(ctx: Context): Boolean {
        if (!sessionOk) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "no_session")
            return false
        }
        if (sessionToken.isBlank() && !BuildConfig.DEBUG) {
            // release: require non-empty token from panel after OTP
            ThreatReport.emit(ctx, "GATE_BLOCK", "empty_token")
            return false
        }
        val t = Tamper.evaluate(ctx)
        if (Tamper.expectedCertSha256.isNotEmpty() && !t.ok) {
            ThreatReport.emit(ctx, "GATE_BLOCK", t.reasons.joinToString("|"))
            sessionOk = false
            return false
        }
        if (Guard.hostile() || Guard.degraded) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "hostile_env")
            // RELEASE: hard block. DEBUG: allow for development.
            if (!BuildConfig.DEBUG) {
                sessionOk = false
                return false
            }
        }
        return true
    }

    fun unlock(token: String, license: String) {
        sessionToken = token
        licenseBound = license
        sessionOk = true
    }

    fun lock() {
        sessionOk = false
        sessionToken = ""
        licenseBound = ""
    }

    fun onThreat() {
        lock()
    }
}

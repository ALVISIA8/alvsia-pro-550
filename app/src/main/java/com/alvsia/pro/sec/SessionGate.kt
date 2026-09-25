package com.alvsia.pro.sec

import android.content.Context
import com.alvsia.pro.BuildConfig

/**
 * Hard session gate — release never soft-allows tools.
 */
object SessionGate {
    @Volatile var sessionOk: Boolean = false
    @Volatile var sessionToken: String = ""
    @Volatile var licenseBound: String = ""
    @Volatile private var unlockAtMs: Long = 0L

    fun allowTools(ctx: Context): Boolean {
        if (!sessionOk) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "no_session")
            return false
        }
        if (sessionToken.isBlank()) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "empty_token")
            sessionOk = false
            return false
        }
        // Session max lifetime 12h wall clock
        if (unlockAtMs > 0 && System.currentTimeMillis() - unlockAtMs > 12L * 3600_000L) {
            lock()
            ThreatReport.emit(ctx, "GATE_BLOCK", "session_expired")
            return false
        }
        val t = Tamper.evaluate(ctx)
        if (Tamper.expectedCertSha256.isNotEmpty() && !t.ok) {
            ThreatReport.emit(ctx, "GATE_BLOCK", t.reasons.joinToString("|"))
            lock()
            return false
        }
        if (Guard.hostile() || Guard.degraded) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "hostile_env")
            lock()
            return false
        }
        return true
    }

    fun unlock(token: String, license: String) {
        if (token.isBlank()) return
        sessionToken = token
        licenseBound = license
        unlockAtMs = System.currentTimeMillis()
        sessionOk = true
    }

    fun lock() {
        sessionOk = false
        sessionToken = ""
        licenseBound = ""
        unlockAtMs = 0L
    }

    fun onThreat() = lock()
}

package com.alvsia.pro.sec

import android.content.Context

/**
 * Blocks tool execution if signature mismatch (when CERT set) or hostile env degraded.
 */
object SessionGate {
    @Volatile var sessionOk: Boolean = false

    fun allowTools(ctx: Context): Boolean {
        if (!sessionOk) return false
        val t = Tamper.evaluate(ctx)
        if (Tamper.expectedCertSha256.isNotEmpty() && !t.ok) {
            ThreatReport.emit(ctx, "GATE_BLOCK", t.reasons.joinToString("|"))
            return false
        }
        if (Guard.degraded) {
            ThreatReport.emit(ctx, "GATE_DEGRADED", "hostile")
            // soft: still allow but reported
        }
        return true
    }

    fun onThreat() {
        sessionOk = false
    }
}

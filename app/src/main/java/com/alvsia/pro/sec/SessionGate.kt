package com.alvsia.pro.sec

import android.content.Context
import java.util.concurrent.atomic.AtomicInteger

/**
 * ALVISIA PRO 5.5.0 — SessionGate HARDENED
 *
 * Hard gate preventing tool access under any threat condition.
 * Session lifetime: 12 h max, must pass every gate check.
 *
 * Extra hardening vs original:
 *  - Threat counter: 3 strikes → process kill.
 *  - Token validation: HMAC-SHA256 structure check (stub — implement in Vault).
 *  - All-zero token explicitly rejected.
 *  - Guard.hostile() called inline on allowTools().
 *  - IntegrityBomb run on every allowTools() call (not just tick).
 */
object SessionGate {
    @Volatile var sessionOk: Boolean = false
    @Volatile var sessionToken: String = ""
    @Volatile var licenseBound: String = ""
    @Volatile private var unlockAtMs: Long = 0L
    private val threatCount = AtomicInteger(0)

    private const val SESSION_MAX_MS = 12L * 3600_000L

    fun allowTools(ctx: Context): Boolean {
        // 1. Basic session state
        if (!sessionOk) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "no_session")
            return false
        }
        if (sessionToken.isBlank() || sessionToken.all { it == '0' }) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "empty_token")
            lock(); return false
        }

        // 2. Session lifetime
        if (unlockAtMs > 0 && System.currentTimeMillis() - unlockAtMs > SESSION_MAX_MS) {
            lock()
            ThreatReport.emit(ctx, "GATE_BLOCK", "session_expired")
            return false
        }

        // 3. Certificate / tamper check (every call)
        val t = Tamper.evaluate(ctx)
        if (Tamper.expectedCertSha256.isNotEmpty() && !t.ok) {
            ThreatReport.emit(ctx, "GATE_BLOCK", t.reasons.joinToString("|"))
            lock(); return false
        }

        // 4. Integrity bomb (every call)
        val bomb = IntegrityBomb.evaluate(ctx)
        if (!bomb.clean) {
            val hardReasons = bomb.reasons.filter {
                it.startsWith("cert_") || it.startsWith("dex_") || it == "clone_container"
            }
            if (hardReasons.isNotEmpty()) {
                ThreatReport.emit(ctx, "GATE_BLOCK", "bomb:${hardReasons.joinToString("|")}")
                lock(); return false
            }
        }

        // 5. Live hostile check
        if (Guard.hostile() || Guard.degraded) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "hostile_env")
            lock(); return false
        }

        return true
    }

    fun unlock(token: String, license: String) {
        if (token.isBlank()) return
        sessionToken = token
        licenseBound = license
        unlockAtMs = System.currentTimeMillis()
        sessionOk = true
        threatCount.set(0)
    }

    fun lock() {
        sessionOk = false
        sessionToken = ""
        licenseBound = ""
        unlockAtMs = 0L
    }

    fun onThreat() {
        lock()
        val n = threatCount.incrementAndGet()
        if (n >= 3) {
            // Hard exit — prevent bypass loop
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }
}

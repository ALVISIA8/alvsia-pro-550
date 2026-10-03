package com.alvsia.pro.sec

import android.content.Context
import android.content.SharedPreferences

object SessionGate {

    private const val PREF        = "sg_v2"
    private const val KEY_TOKEN   = "tok"
    private const val KEY_LICENSE = "lic"
    private const val KEY_GRANTED = "granted"
    private const val KEY_TS      = "ts"
    private const val KEY_STRIKES = "strikes"
    private const val SESSION_TTL = 12 * 60 * 60 * 1000L   // 12 h
    private const val MAX_STRIKES = 3

    // ── Static context cache (set on first unlock / allowTools) ──────
    @Volatile private var _appCtx: Context? = null

    private fun prefs(ctx: Context): SharedPreferences {
        _appCtx = ctx.applicationContext
        return ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)
    }

    // ── Public state properties (used by ToolEngine) ─────────────────

    val sessionOk: Boolean
        get() {
            val ctx = _appCtx ?: return false
            val p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            val granted = p.getBoolean(KEY_GRANTED, false)
            val ts      = p.getLong(KEY_TS, 0L)
            return granted && (System.currentTimeMillis() - ts) <= SESSION_TTL
        }

    val sessionToken: String
        get() {
            val ctx = _appCtx ?: return ""
            return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString(KEY_TOKEN, "") ?: ""
        }

    // ── Gate ─────────────────────────────────────────────────────────

    fun allowTools(ctx: Context): Boolean {
        _appCtx = ctx.applicationContext

        // 1. Native anti-debug gate
        if (!NativeGate.preCheck()) {
            val reason = "native_precheck_fail"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        // 2. Hook / tracer check
        if (Guard.hostile(ctx)) {
            val reason = "guard_hostile:${Guard.lastReason}"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        // 3. Integrity check
        if (IntegrityBomb.isCompromised(ctx)) {
            val reason = "integrity_fail:${IntegrityBomb.lastReason}"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        val p       = prefs(ctx)
        val granted = p.getBoolean(KEY_GRANTED, false)
        val ts      = p.getLong(KEY_TS, 0L)
        val strikes = p.getInt(KEY_STRIKES, 0)
        val now     = System.currentTimeMillis()

        if (strikes >= MAX_STRIKES) {
            ThreatReport.emit(ctx, "GATE_BLOCK", "strike_limit")
            throw SecurityException("BLOCKED:strike_limit")
        }

        if (!granted) {
            throw SecurityException("BLOCKED:no_session")
        }

        if (now - ts > SESSION_TTL) {
            lock(ctx)
            throw SecurityException("BLOCKED:session_expired")
        }

        return true
    }

    fun unlock(ctx: Context, token: String, license: String) {
        if (token.isBlank()) return
        if (!NativeGate.preCheck()) return
        prefs(ctx).edit()
            .putBoolean(KEY_GRANTED, true)
            .putString(KEY_TOKEN, token)
            .putString(KEY_LICENSE, license)
            .putLong(KEY_TS, System.currentTimeMillis())
            .putInt(KEY_STRIKES, 0)
            .apply()
    }

    /** Legacy 2-arg unlock called by MainActivity (no ctx arg) */
    fun unlock(token: String, license: String) {
        val ctx = _appCtx ?: return
        unlock(ctx, token, license)
    }

    /** Legacy no-arg lock — called by MainActivity / RaspEngine */
    fun lock() {
        val ctx = _appCtx ?: return
        lock(ctx)
    }

    fun lock(ctx: Context) {
        prefs(ctx).edit()
            .putBoolean(KEY_GRANTED, false)
            .putLong(KEY_TS, 0L)
            .apply()
    }

    /** Called by RaspEngine on hard threat */
    fun onThreat() {
        val ctx = _appCtx ?: return
        addStrike(ctx)
        val strikes = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getInt(KEY_STRIKES, 0)
        if (strikes >= MAX_STRIKES) lock(ctx)
    }

    fun addStrike(ctx: Context) {
        val p = prefs(ctx)
        p.edit().putInt(KEY_STRIKES, p.getInt(KEY_STRIKES, 0) + 1).apply()
    }

    fun isLocked(ctx: Context): Boolean {
        val p   = prefs(ctx)
        val granted = p.getBoolean(KEY_GRANTED, false)
        val ts      = p.getLong(KEY_TS, 0L)
        return !granted || (System.currentTimeMillis() - ts > SESSION_TTL)
    }
}

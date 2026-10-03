package com.alvsia.pro.sec

import android.content.Context
import android.content.SharedPreferences
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.IntegrityBomb
import com.alvsia.pro.sec.NativeGate
import com.alvsia.pro.sec.ThreatReport

object SessionGate {

    private const val PREF = "sg_v2"
    private const val KEY_TOKEN    = "tok"
    private const val KEY_LICENSE  = "lic"
    private const val KEY_GRANTED  = "granted"
    private const val KEY_TS       = "ts"
    private const val KEY_STRIKES  = "strikes"
    private const val SESSION_TTL  = 12 * 60 * 60 * 1000L  // 12 h
    private const val MAX_STRIKES  = 3

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun allowTools(ctx: Context): Boolean {
        // 1. Native integrity pre-check
        if (!NativeGate.preCheck()) {
            val reason = "native_precheck_fail"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        // 2. System-level hostility check
        if (Guard.hostile(ctx)) {
            val reason = "guard_hostile:${Guard.lastReason}"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        // 3. App integrity check
        if (IntegrityBomb.isCompromised(ctx)) {
            val reason = "integrity_fail:${IntegrityBomb.lastReason}"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            lock(ctx)
            throw SecurityException("BLOCKED:$reason")
        }

        val p = prefs(ctx)
        val granted  = p.getBoolean(KEY_GRANTED, false)
        val ts       = p.getLong(KEY_TS, 0L)
        val strikes  = p.getInt(KEY_STRIKES, 0)
        val now      = System.currentTimeMillis()

        if (strikes >= MAX_STRIKES) {
            val reason = "strike_limit"
            ThreatReport.emit(ctx, "GATE_BLOCK", reason)
            throw SecurityException("BLOCKED:$reason")
        }

        if (!granted) {
            val reason = "no_session"
            throw SecurityException("BLOCKED:$reason")
        }

        if (now - ts > SESSION_TTL) {
            lock(ctx)
            val reason = "session_expired"
            throw SecurityException("BLOCKED:$reason")
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

    fun addStrike(ctx: Context) {
        val p = prefs(ctx)
        val s = p.getInt(KEY_STRIKES, 0) + 1
        p.edit().putInt(KEY_STRIKES, s).apply()
    }

    fun lock(ctx: Context) {
        prefs(ctx).edit()
            .putBoolean(KEY_GRANTED, false)
            .putLong(KEY_TS, 0L)
            .apply()
    }

    fun isLocked(ctx: Context): Boolean {
        val p = prefs(ctx)
        val granted = p.getBoolean(KEY_GRANTED, false)
        val ts      = p.getLong(KEY_TS, 0L)
        val now     = System.currentTimeMillis()
        return !granted || (now - ts > SESSION_TTL)
    }
}

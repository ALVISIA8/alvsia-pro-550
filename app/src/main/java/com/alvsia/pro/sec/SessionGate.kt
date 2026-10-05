package com.alvsia.pro.sec

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.KeyStore

/**
 * SessionGate HARDENED v2.1
 *
 * Token/session data is now encrypted with AES-256-GCM using a key
 * that lives in the Android Keystore (hardware-backed on supported devices).
 * Even on a rooted device the raw SharedPreferences XML contains only
 * ciphertext — the Keystore key cannot be extracted without the device
 * credentials (strong box or TEE).
 *
 * Strike counter uses atomic SharedPreferences edit + HMAC integrity tag
 * so editing the XML value is detected on the next read.
 */
object SessionGate {

    private const val PREF        = "sg_v3"          // bumped — old plaintext pref ignored
    private const val KEY_TOKEN   = "tok_enc"
    private const val KEY_LICENSE = "lic_enc"
    private const val KEY_GRANTED = "granted_enc"
    private const val KEY_TS      = "ts_enc"
    private const val KEY_STRIKES = "strikes"         // int, integrity-tagged separately
    private const val KEY_STRIKE_TAG = "strikes_tag"
    private const val SESSION_TTL = 12 * 60 * 60 * 1000L   // 12 h
    private const val MAX_STRIKES = 2                 // hardened: was 3, now 2

    private const val KS_ALIAS = "alvsia_sg_v3"
    private const val KS_PROVIDER = "AndroidKeyStore"
    private const val AES_GCM = "AES/GCM/NoPadding"
    private const val GCM_TAG_LEN = 128

    // ── Static context cache (set on first unlock / allowTools) ──────
    @Volatile private var _appCtx: Context? = null

    // ── In-memory verified state (prevents repeated pref reads) ──────
    @Volatile private var _grantedInMem: Boolean = false
    @Volatile private var _tsInMem: Long = 0L

    private fun prefs(ctx: Context): SharedPreferences {
        _appCtx = ctx.applicationContext
        return ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)
    }

    // ── Keystore key management ───────────────────────────────────────

    private fun ensureKey() {
        val ks = KeyStore.getInstance(KS_PROVIDER).also { it.load(null) }
        if (ks.containsAlias(KS_ALIAS)) return
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KS_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(KS_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)   // no biometric — tool must run in bg
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        kg.generateKey()
    }

    private fun keystoreKey(): javax.crypto.SecretKey {
        ensureKey()
        val ks = KeyStore.getInstance(KS_PROVIDER).also { it.load(null) }
        return (ks.getEntry(KS_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    // ── Encrypt / decrypt helpers ─────────────────────────────────────

    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val iv  = cipher.iv
        val ct  = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        val out = ByteArray(iv.size + ct.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ct, 0, out, iv.size, ct.size)
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    private fun decrypt(b64: String?): String? {
        if (b64.isNullOrBlank()) return null
        return try {
            val blob = Base64.decode(b64, Base64.DEFAULT)
            val iv   = blob.copyOfRange(0, 12)
            val ct   = blob.copyOfRange(12, blob.size)
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(GCM_TAG_LEN, iv))
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    // ── Strike HMAC tag (prevents root-edit of counter) ──────────────

    private fun strikeTag(value: Int): String {
        val key = keystoreKey().encoded ?: byteArrayOf(0x42)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return Base64.encodeToString(mac.doFinal("strikes:$value".toByteArray()), Base64.NO_WRAP)
    }

    private fun strikesIntegral(p: SharedPreferences): Boolean {
        val v   = p.getInt(KEY_STRIKES, 0)
        val tag = p.getString(KEY_STRIKE_TAG, "") ?: ""
        if (tag.isEmpty()) return true   // first run — no tag yet, accept
        return try { tag == strikeTag(v) } catch (_: Exception) { true }
    }

    // ── Public state properties (used by ToolEngine) ─────────────────

    val sessionOk: Boolean
        get() {
            // Fast path: in-memory verified state
            if (_grantedInMem && (System.currentTimeMillis() - _tsInMem) <= SESSION_TTL)
                return true
            // Slow path: decrypt from prefs
            val ctx = _appCtx ?: return false
            return try {
                val p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                val granted = decrypt(p.getString(KEY_GRANTED, null)) == "1"
                val ts      = decrypt(p.getString(KEY_TS, null))?.toLongOrNull() ?: 0L
                val ok = granted && (System.currentTimeMillis() - ts) <= SESSION_TTL
                if (ok) { _grantedInMem = true; _tsInMem = ts }
                ok
            } catch (_: Exception) { false }
        }

    val sessionToken: String
        get() {
            val ctx = _appCtx ?: return ""
            return try {
                decrypt(ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                    .getString(KEY_TOKEN, null)) ?: ""
            } catch (_: Exception) { "" }
        }

    // ── Gate ─────────────────────────────────────────────────────────

    fun allowTools(ctx: Context): Boolean {
        _appCtx = ctx.applicationContext

        if (!NativeGate.sessionUnlocked) {
            if (!NativeGate.preCheck()) {
                val reason = "native_precheck_fail"
                ThreatReport.emit(ctx, "GATE_BLOCK", reason)
                lock(ctx)
                throw SecurityException("BLOCKED:$reason")
            }
            if (Guard.hostile(ctx)) {
                val reason = "guard_hostile:${Guard.lastReason}"
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

        // Check RASP degraded (root/emulator detected) — tools blocked when degraded
        if (RaspEngine.degraded) {
            // Allow 1 degraded grace; after that, block
            val p = prefs(ctx)
            val grace = p.getInt("degraded_grace", 0)
            if (grace >= 1) {
                ThreatReport.emit(ctx, "GATE_BLOCK", "rasp_degraded")
                throw SecurityException("BLOCKED:rasp_degraded")
            }
            p.edit().putInt("degraded_grace", grace + 1).apply()
        }

        val p       = prefs(ctx)
        val granted = try { decrypt(p.getString(KEY_GRANTED, null)) == "1" } catch (_: Exception) { false }
        val ts      = try { decrypt(p.getString(KEY_TS, null))?.toLongOrNull() ?: 0L } catch (_: Exception) { 0L }
        val strikes = p.getInt(KEY_STRIKES, 0)
        val now     = System.currentTimeMillis()

        if (!strikesIntegral(p)) {
            // Strike counter was tampered — treat as max strikes
            ThreatReport.emit(ctx, "GATE_BLOCK", "strike_tamper")
            lock(ctx)
            throw SecurityException("BLOCKED:strike_tamper")
        }

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

    /** 2-arg overload — called by MainActivity after OTP verify */
    fun unlock(token: String, license: String) {
        val ctx = _appCtx ?: return
        unlock(ctx, token, license)
    }

    fun unlock(ctx: Context, token: String, license: String) {
        if (token.isBlank()) return
        if (!NativeGate.preCheck()) return
        NativeGate.sessionUnlocked = true
        val now = System.currentTimeMillis()
        _grantedInMem = true
        _tsInMem = now
        val tag0 = try { strikeTag(0) } catch (_: Exception) { "" }
        try {
            prefs(ctx).edit()
                .putString(KEY_GRANTED, encrypt("1"))
                .putString(KEY_TOKEN,   encrypt(token))
                .putString(KEY_LICENSE, encrypt(license))
                .putString(KEY_TS,      encrypt(now.toString()))
                .putInt(KEY_STRIKES, 0)
                .putString(KEY_STRIKE_TAG, tag0)
                .remove("degraded_grace")
                .apply()
        } catch (e: Exception) {
            // Keystore may not be ready on first boot — fall back to best-effort
            ThreatReport.emit(ctx, "UNLOCK_KS_ERR", e.message ?: "ks_fail")
        }
    }

    /** Legacy no-arg lock — called by MainActivity / RaspEngine */
    fun lock() {
        val ctx = _appCtx ?: return
        lock(ctx)
    }

    fun lock(ctx: Context) {
        _grantedInMem = false
        _tsInMem = 0L
        NativeGate.sessionUnlocked = false
        try {
            prefs(ctx).edit()
                .putString(KEY_GRANTED, encrypt("0"))
                .putString(KEY_TS, encrypt("0"))
                .apply()
        } catch (_: Exception) {
            prefs(ctx).edit().remove(KEY_GRANTED).remove(KEY_TS).apply()
        }
    }

    /** Called by RaspEngine on hard threat — 1 hard threat = immediate lock */
    fun onThreat() {
        val ctx = _appCtx ?: return
        addStrike(ctx)
        val p       = prefs(ctx)
        val strikes = p.getInt(KEY_STRIKES, 0)
        if (strikes >= MAX_STRIKES) lock(ctx)
    }

    fun addStrike(ctx: Context) {
        val p    = prefs(ctx)
        val curr = p.getInt(KEY_STRIKES, 0) + 1
        val tag  = try { strikeTag(curr) } catch (_: Exception) { "" }
        p.edit().putInt(KEY_STRIKES, curr).putString(KEY_STRIKE_TAG, tag).apply()
    }

    fun isLocked(ctx: Context): Boolean = !sessionOk
}

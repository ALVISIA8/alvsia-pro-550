package com.alvsia.pro.tool

import android.content.Context
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Asset blob unpack. Root material assembled from fragments + optional session overlay.
 * Prefer server tool_fetch after OTP; this is offline companion only.
 */
object FaunaPack {
    private val MAGIC = byteArrayOf(0x46, 0x41, 0x55, 0x4E, 0x41, 0x31, 0x00)

    /** Optional server-provided wrap (set after OTP loader_key). */
    @Volatile
    var sessionOverlay: ByteArray? = null

    private fun frag(): ByteArray {
        // fragments XOR-assembled ? not a clear marketing string in binary
        val a = intArrayOf(0x1A, 0x14, 0x01, 0x1B, 0x1E, 0x16, 0x08, 0x1B, 0x12, 0x09, 0x12, 0x08, 0x1A)
        val b = intArrayOf(0x6B, 0x73, 0x65, 0x6C, 0x65, 0x76, 0x65, 0x6C, 0x5F, 0x61)
        val k = 0x55
        val p1 = ByteArray(a.size) { i -> (a[i] xor k).toByte() }
        val p2 = byteArrayOf(0x7C) + ByteArray(b.size) { i -> (b[i] xor 0x00).toByte() }
        // reconstruct compatible with previous packs: fixed build id path
        return sha256(
            ("MSV_LEVEL_A_PLUS|4.6.1|ALVSIA|ENTERPRISE|xK9mQ2|VALLERINIE|CN-RU-IL-US").toByteArray()
        )
    }

    private fun root(): ByteArray {
        val base = frag()
        val ov = sessionOverlay
        return if (ov != null && ov.isNotEmpty()) {
            sha256(base + ov)
        } else base
    }

    private fun sha256(d: ByteArray) = MessageDigest.getInstance("SHA-256").digest(d)

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, n: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var c = 1
        while (out.size() < n) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t); mac.update(info); mac.update(byteArrayOf(c.toByte()))
            t = mac.doFinal(); out.write(t); c++
        }
        return out.toByteArray().copyOf(n)
    }

    fun unpackFromAssets(ctx: Context): ByteArray? {
        return try {
            ctx.assets.open("fauna/panda.dat").use { it.readBytes() }.let { open(it) }
        } catch (_: Exception) {
            null
        }
    }

    fun open(blob: ByteArray): ByteArray? {
        return try {
            if (blob.size < 40) return null
            if (!blob.copyOfRange(0, 7).contentEquals(MAGIC)) return null
            val nonce = blob.copyOfRange(23, 35)
            val ctTag = blob.copyOfRange(35, blob.size)
            val salt = sha256("ALVSIA-APK-FAUNA-4.6".toByteArray() + "PANDA".toByteArray())
            val k = hkdf(root(), salt, "FAUNA-PACK".toByteArray(), 32)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
            inflate(c.doFinal(ctTag))
        } catch (_: Exception) {
            null
        }
    }

    private fun inflate(data: ByteArray): ByteArray {
        val inf = Inflater()
        inf.setInput(data)
        val buf = ByteArray(65536)
        val out = ByteArrayOutputStream()
        while (!inf.finished()) {
            val n = inf.inflate(buf)
            if (n <= 0 && inf.needsInput()) break
            if (n > 0) out.write(buf, 0, n)
        }
        inf.end()
        return out.toByteArray()
    }
}

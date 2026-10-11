package com.alvsia.pro.panel

import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Crypto {
    private val MARKER = byteArrayOf(
        0x41, 0x4C, 0x56, 0x53, 0x49, 0x41, 0x5F, 0x56, 0x32, 0x7C
    ) // ALVSIA_V2|

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(s: String): String =
        sha256(s.toByteArray()).joinToString("") { "%02x".format(it) }

    fun transportKey(nonceHex: String): ByteArray {
        val nonce = hexToBytes(nonceHex)
        return sha256(MARKER + nonce)
    }

    fun aesCbcEncrypt(key: ByteArray, ivAscii16: String, plain: ByteArray): ByteArray {
        val iv = ivAscii16.take(16).padEnd(16, '0').toByteArray()
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(plain)
    }

    fun aesCbcDecrypt(key: ByteArray, ivBytes: ByteArray, cipherBytes: ByteArray): ByteArray {
        val iv = if (ivBytes.size >= 16) ivBytes.copyOf(16) else ByteArray(16).also {
            System.arraycopy(ivBytes, 0, it, 0, ivBytes.size)
        }
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(cipherBytes)
    }

    fun b64(data: ByteArray): String = Base64.encodeToString(data, Base64.NO_WRAP)
    fun b64d(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)

    fun solvePow(prefix: String, diff: Int): String {
        if (prefix.isEmpty() || diff <= 0) return "0"
        val need = "0".repeat(diff)
        for (i in 0 until 5_000_000) {
            val n = i.toString(16)
            if (sha256Hex(prefix + n).startsWith(need)) return n
        }
        return "0"
    }

    fun solveMechanic(mechanicB64: String): Int {
        val expr = String(b64d(mechanicB64)).trim()
        val m = Regex("""^(-?\d+)\s*([+\-*/])\s*(-?\d+)$""").matchEntire(expr)
            ?: return 0
        val a = m.groupValues[1].toInt()
        val b = m.groupValues[3].toInt()
        return when (m.groupValues[2]) {
            "+" -> a + b
            "-" -> a - b
            "*" -> a * b
            "/" -> if (b != 0) a / b else 0
            else -> 0
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val h = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(h.length / 2) { i ->
            h.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

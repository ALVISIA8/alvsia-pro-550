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

    fun aesCbcEncrypt(key: ByteArray, nonceHex: String, plain: ByteArray): ByteArray {
        val nonce = hexToBytes(nonceHex)
        require(nonce.size >= 16) { "nonce must contain at least 16 bytes" }
        val iv = nonce.copyOfRange(0, 16)
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
        require(prefix.isNotBlank()) { "PoW prefix is missing" }
        require(diff in 1..6) { "Unsupported PoW difficulty: $diff" }
        val need = "0".repeat(diff)
        for (i in 0 until 5_000_000) {
            val n = i.toString()
            if (sha256Hex(prefix + n).startsWith(need)) return n
        }
        throw IllegalStateException("PoW solution not found within search limit")
    }

    fun solveMechanic(challenge: String): Int {
        val pattern = Regex("""^(-?[0-9]+)\s*([+*/-])\s*(-?[0-9]+)$""")
        val direct = challenge.trim()
        val expr = if (pattern.matches(direct)) direct else try {
            String(b64d(challenge), Charsets.UTF_8).trim()
        } catch (_: Exception) {
            direct
        }
        val m = pattern.matchEntire(expr)
            ?: throw IllegalArgumentException("Unsupported captcha expression")
        val a = m.groupValues[1].toIntOrNull()
            ?: throw IllegalArgumentException("Captcha operand is out of range")
        val b = m.groupValues[3].toIntOrNull()
            ?: throw IllegalArgumentException("Captcha operand is out of range")
        return when (m.groupValues[2]) {
            "+" -> Math.addExact(a, b)
            "-" -> Math.subtractExact(a, b)
            "*" -> Math.multiplyExact(a, b)
            "/" -> {
                require(b != 0 && a % b == 0) { "Invalid captcha division" }
                a / b
            }
            else -> throw IllegalArgumentException("Unsupported captcha operator")
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val h = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(h.length / 2) { i ->
            h.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

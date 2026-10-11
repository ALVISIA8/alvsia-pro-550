package com.alvsia.pro.tool

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object LevelACore {
    private val MAGIC = byteArrayOf(0x4D, 0x53, 0x56, 0x4C, 0x56, 0x4C, 0x42, 0x03)
    private val BUILD = "ALVSIA-4.6.1-LA".toByteArray(Charsets.US_ASCII)

    private fun rootKey(): ByteArray = sha256(
        "MSV_LEVEL_A_PLUS|4.6.1|ALVSIA|ENTERPRISE|xK9mQ2|VALLERINIE|CN-RU-IL-US"
            .toByteArray(Charsets.UTF_8)
    )

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, n: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var c = 1
        while (out.size() < n) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(byteArrayOf(c.toByte()))
            t = mac.doFinal()
            out.write(t)
            c++
        }
        return out.toByteArray().copyOf(n)
    }

    private fun gcmOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ctTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ctTag)
    }

    private fun zlibDecompress(data: ByteArray): ByteArray {
        val inflater = Inflater()
        inflater.setInput(data)
        val buf = ByteArray(65536)
        val out = ByteArrayOutputStream()
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            if (n <= 0 && inflater.needsInput()) break
            if (n > 0) out.write(buf, 0, n)
        }
        inflater.end()
        return out.toByteArray()
    }

    fun tryDecrypt(blob: ByteArray): ByteArray? {
        return try {
            if (blob.size < 100) return blob
            if (!blob.copyOfRange(0, 8).contentEquals(MAGIC)) return blob
            val ver = blob[8].toInt() and 0xFF
            if (ver != 3) return null
            val lab = blob.copyOfRange(9, 25)
            val aad1 = blob.copyOfRange(0, 25)
            val salt2 = blob.copyOfRange(25, 57)
            val n2 = blob.copyOfRange(57, 69)
            val body = blob.copyOfRange(0, blob.size - 64)
            val mac = blob.copyOfRange(blob.size - 64, blob.size)
            val macEngine = Mac.getInstance("HmacSHA512")
            macEngine.init(SecretKeySpec(rootKey(), "HmacSHA512"))
            if (!macEngine.doFinal(body).contentEquals(mac)) return null
            val c2 = blob.copyOfRange(69, blob.size - 64)
            val k2 = hkdf(rootKey(), salt2, "L2-WRAP".toByteArray(Charsets.US_ASCII), 32)
            val layer1 = gcmOpen(k2, n2, aad1 + salt2, c2)
            val n1 = layer1.copyOfRange(0, 12)
            val c1 = layer1.copyOfRange(12, layer1.size)
            // salt = sha256(BUILD + original label). Original label was padded in lab with zeros.
            val labelOrig = lab.filter { it != 0.toByte() }.toByteArray()
            val salt = sha256(BUILD + labelOrig)
            val k1 = hkdf(rootKey(), salt, "L1-WRAP".toByteArray(Charsets.US_ASCII), 32)
            val compressed = gcmOpen(k1, n1, aad1, c1)
            zlibDecompress(compressed)
        } catch (_: Exception) {
            null
        }
    }
}

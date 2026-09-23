package com.alvsia.pro.asset

import android.content.Context
import com.alvsia.pro.sec.Tamper
import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object AssetVault {
    private val MAGIC = byteArrayOf(0x41, 0x4C, 0x56, 0x53, 0x41, 0x31, 0x00)

    private fun key(ctx: Context): ByteArray {
        val cert = Tamper.signingCertSha256(ctx).ifBlank {
            "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
        }
        val raw = (ctx.packageName + "|" + cert.lowercase() + "|ALV-ASSET-v1").toByteArray()
        return MessageDigest.getInstance("SHA-256").digest(raw)
    }

    private fun openBlob(blob: ByteArray, key: ByteArray): ByteArray? {
        return try {
            if (blob.size < 7 + 12 + 16) return null
            if (!blob.copyOfRange(0, 7).contentEquals(MAGIC)) return null
            val nonce = blob.copyOfRange(7, 19)
            val ct = blob.copyOfRange(19, blob.size)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.doFinal(ct)
        } catch (_: Exception) {
            null
        }
    }

    fun loadSealedMap(ctx: Context): Map<String, ByteArray> {
        val k = key(ctx)
        val out = mutableMapOf<String, ByteArray>()
        return try {
            val am = ctx.assets
            val idxBlob = am.open("nx/i.dat").use { it.readBytes() }
            val idx = openBlob(idxBlob, k)?.toString(Charsets.UTF_8) ?: return emptyMap()
            for (line in idx.lines()) {
                val parts = line.split("=", limit = 2)
                if (parts.size != 2) continue
                val logical = parts[0].trim()
                val file = parts[1].trim()
                if (logical.isEmpty() || file.isEmpty()) continue
                val blob = am.open("nx/$file").use { it.readBytes() }
                val plain = openBlob(blob, k) ?: continue
                out[logical] = plain
            }
            out
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun materializeJars(ctx: Context, jarsDir: File): Int {
        jarsDir.mkdirs()
        var n = 0
        for ((name, bytes) in loadSealedMap(ctx)) {
            if (!name.endsWith(".jar")) continue
            val dest = File(jarsDir, name)
            if (dest.exists() && dest.length() == bytes.size.toLong()) {
                n++
                continue
            }
            dest.writeBytes(bytes)
            try {
                dest.setReadable(true, true)
                dest.setWritable(true, true)
            } catch (_: Exception) {
            }
            n++
        }
        return n
    }
}

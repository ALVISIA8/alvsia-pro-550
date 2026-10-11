package com.alvsia.pro.tool

import android.content.Context
import java.io.File
import java.security.SecureRandom

/**
 * Holds core bytes only in process memory / short-lived cache file then deletes.
 * No permanent tool source on device.
 */
class CoreSession {
    @Volatile private var blob: ByteArray? = null
    @Volatile private var tempFile: File? = null

    fun loadFromMemory(data: ByteArray) {
        wipe()
        blob = data.copyOf()
    }

    fun size(): Int = blob?.size ?: 0

    fun isReady(): Boolean = blob != null && blob!!.isNotEmpty()

    /** Optional: write ELF to app-private cache for System.load, then delete after. */
    fun materializeTemp(context: Context, prefix: String = "c"): File? {
        val data = blob ?: return null
        val dir = File(context.cacheDir, "x")
        if (!dir.exists()) dir.mkdirs()
        val rnd = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val name = prefix + rnd.joinToString("") { "%02x".format(it) }
        val f = File(dir, name)
        f.writeBytes(data)
        tempFile = f
        return f
    }

    fun wipe() {
        blob?.fill(0)
        blob = null
        try {
            tempFile?.let { f ->
                if (f.exists()) {
                    val n = f.length().toInt().coerceAtMost(64 * 1024 * 1024)
                    // best-effort overwrite
                    f.writeBytes(ByteArray(n.coerceAtLeast(0)))
                    f.delete()
                }
            }
        } catch (_: Exception) {
        }
        tempFile = null
        // wipe cache dir x
    }

    fun wipeCacheDir(context: Context) {
        try {
            File(context.cacheDir, "x").listFiles()?.forEach { it.delete() }
        } catch (_: Exception) {
        }
    }
}

package com.alvsia.pro.tool

import android.content.Context
import android.os.Environment
import java.io.File

object WorkPaths {
    @Volatile private var appFallback: File? = null

    fun bindApp(ctx: Context) {
        if (appFallback == null) {
            appFallback = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "ALVSIA").also { it.mkdirs() }
        }
    }

    fun alvsiaRoot(): File {
        return try {
            val dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val root = File(dl, "ALVSIA")
            if (!root.exists()) root.mkdirs()
            if (root.exists() && root.canWrite()) root
            else appFallback ?: root
        } catch (_: Exception) {
            appFallback ?: File("/sdcard/Download/ALVSIA")
        }
    }

    fun dirIn(): File = File(alvsiaRoot(), "IN").also { it.mkdirs() }
    fun dirWork(): File = File(alvsiaRoot(), "WORK").also { it.mkdirs() }
    fun dirOut(): File = File(alvsiaRoot(), "OUT").also { it.mkdirs() }

    fun moduleOut(moduleId: Int): File {
        val name = moduleName(moduleId)
        return File(dirOut(), name).also { it.mkdirs() }
    }

    fun moduleIn(moduleId: Int): File {
        val name = moduleName(moduleId)
        return File(dirIn(), name).also { it.mkdirs() }
    }

    fun moduleWork(moduleId: Int): File {
        val name = moduleName(moduleId)
        return File(dirWork(), name).also { it.mkdirs() }
    }

    /** Back-compat for older calls */
    fun moduleDir(moduleId: Int, sub: String = "out"): File {
        return when (sub.lowercase()) {
            "in", "input" -> moduleIn(moduleId)
            "work" -> moduleWork(moduleId)
            else -> moduleOut(moduleId)
        }
    }

    private fun moduleName(moduleId: Int): String = when (moduleId) {
        1, 2, 3 -> "PAK"
        4 -> "OBB"
        5 -> "LUA"
        6 -> "SCAN"
        7 -> "WORKSPACE"
        8 -> "REPORT"
        9 -> "REBRAND"
        10 -> "SO_ANALYZER"
        11 -> "FRIDA"
        12 -> "XOR"
        13 -> "DECRYPT"
        14 -> "PAK_DEEP"
        15 -> "STRING_RECOVER"
        16 -> "LUA_INJECT"
        17 -> "AUDIT"
        else -> "MISC"
    }

    fun ensureTree() {
        dirIn(); dirWork(); dirOut()
        for (id in 1..17) {
            moduleIn(id); moduleWork(id); moduleOut(id)
        }
    }

    fun readme(ctx: Context) {
        bindApp(ctx)
        ensureTree()
        val f = File(alvsiaRoot(), "README_EN.txt")
        try {
            f.writeText(
                """
                ALVISIA PRO 5.5.0 — Modern I/O
                ====================================
                Root: Download/ALVSIA/
                  IN/<MODULE>/    optional drop zone for inputs
                  WORK/<MODULE>/  temp / intermediate
                  OUT/<MODULE>/   final results (always check here)

                Modules (1..17):
                  1: PAK Unpack       2: PAK Rebuild      3: PAK Compact
                  4: OBB Tools        5: LUA Tools        6: File Scan
                  7: Workspace        8: Export Report    9: Rebrand
                  10: SO Analyzer    11: Frida Tracer    12: XOR Suite
                  13: Decrypt Engine 14: PAK Deep        15: String Recover
                  16: Lua Inject     17: Anti-RE Audit

                Key & OTP: Configured via Owner Panel / Bot
                """.trimIndent()
            )
        } catch (_: Exception) {
        }
    }
}

package com.alvsia.pro.sec

import java.io.File

/**
 * ALVISIA PRO 5.5.0 — MemoryGuard
 * Anti-dump · anti-memory-patch · memory integrity snapshot.
 * Detects: ptrace attach, memory dump tools (Fridump, objection dump),
 *          /proc/self/mem open by external process, /proc/self/pagemap abuse.
 */
object MemoryGuard {

    /**
     * Scan /proc/<pid>/fd for every running process.
     * If any foreign process holds an open fd pointing at /proc/self/mem
     * or /proc/self/pagemap, it's an active dump attempt.
     */
    fun detectDumpAttempt(): List<String> {
        val hits = mutableListOf<String>()
        val selfPid = android.os.Process.myPid()
        try {
            val selfMem = "/proc/$selfPid/mem"
            val selfPage = "/proc/$selfPid/pagemap"
            File("/proc").listFiles()?.forEach { pidDir ->
                val pid = pidDir.name.toIntOrNull() ?: return@forEach
                if (pid == selfPid) return@forEach
                try {
                    pidDir.resolve("fd").listFiles()?.forEach { fd ->
                        try {
                            val target = fd.canonicalPath
                            if (target == selfMem) hits += "mem_open:pid=$pid"
                            if (target == selfPage) hits += "pagemap_open:pid=$pid"
                        } catch (_: Exception) {}
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
        return hits
    }

    /**
     * Check if any process is tracing us (ptrace) beyond ourselves.
     */
    fun detectPtrace(): String? {
        return try {
            val status = File("/proc/self/status").readText()
            val line = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) } ?: return null
            val tpid = line.substringAfter(":").trim().toIntOrNull() ?: 0
            if (tpid > 0) "ptrace:tpid=$tpid" else null
        } catch (_: Exception) { null }
    }

    /**
     * Dump-tool signature check in /proc/<pid>/cmdline for all pids.
     * Fridump3, apkpull, frida-ps, objection.
     */
    fun detectDumpCmdline(): List<String> {
        val hits = mutableListOf<String>()
        val dumpSigs = listOf("fridump", "apkpull", "frida-ps", "objection",
            "memdump", "androiddump", "r2frida", "hluda", "linjector")
        try {
            File("/proc").listFiles()?.forEach { pidDir ->
                if (pidDir.name.toIntOrNull() == null) return@forEach
                try {
                    val cmd = pidDir.resolve("cmdline").readText().replace('\u0000', ' ').lowercase()
                    if (dumpSigs.any { it in cmd }) hits += "dump_proc:$cmd".take(80)
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
        return hits
    }

    /**
     * Wipe a sensitive byte array from memory (best-effort JVM).
     */
    fun wipe(buf: ByteArray?) { buf?.fill(0) }
    fun wipe(buf: CharArray?) { buf?.fill('\u0000') }

    fun allSignals(): List<String> {
        val r = mutableListOf<String>()
        r += detectDumpAttempt()
        detectPtrace()?.let { r += it }
        r += detectDumpCmdline()
        return r.distinct()
    }
}

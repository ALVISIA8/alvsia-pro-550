package com.alvsia.pro.sec

import java.io.File

/**
 * ALVSIA PRO 5.5.0 — NativeGate
 * Second-layer anti-debug / anti-hook gate, pure JVM.
 * Called from SessionGate before unlock and on every allowTools().
 */
object NativeGate {

    fun preCheck(): Boolean {
        if (!timingCheck()) return false
        if (tracerPidNonZero()) return false
        if (stackTainted()) return false
        return true
    }

    /**
     * Tight-loop timing: a debugger in single-step mode inflates this by >10x.
     * 400 ms threshold — slowest production device finishes under 50 ms.
     */
    private fun timingCheck(): Boolean {
        val t0 = System.nanoTime()
        var acc = 0L
        for (i in 0 until 100_000) acc += i.toLong()
        val elapsed = System.nanoTime() - t0
        if (acc == -1L) return false   // sink — prevents loop elimination
        return elapsed < 400_000_000L
    }

    /**
     * Double-read /proc/self/status TracerPid.
     * Two reads disagree → ptrace breakpoint fired between them.
     * Both > 0 → debugger confirmed.
     */
    private fun tracerPidNonZero(): Boolean {
        val v1 = readTracerPid()
        val v2 = readTracerPid()
        if (v1 != v2) return true
        return v1 > 0
    }

    private fun readTracerPid(): Int = try {
        File("/proc/self/status").readText()
            .lineSequence()
            .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
            ?.substringAfter(":")?. trim()?.toIntOrNull() ?: 0
    } catch (_: Exception) { 0 }

    /** Stack frame scan for known hook framework class names. */
    private fun stackTainted(): Boolean {
        return Thread.currentThread().stackTrace.any { frame ->
            val cn = frame.className.lowercase()
            cn.contains("frida") || cn.contains("xposed") ||
            cn.contains("substrate") || cn.contains("dobby") ||
            cn.contains("bhook") || cn.contains("shadowhook") ||
            cn.contains("lsposed") || cn.contains("edxposed") ||
            cn.contains("whale") || cn.contains("sandhook") ||
            cn.contains("epic") || cn.contains("riru") ||
            cn.contains("zygisk") || cn.contains("perseus")
        }
    }
}

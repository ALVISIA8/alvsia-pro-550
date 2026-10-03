package com.alvsia.pro.sec

import java.io.File

/**
 * ALVISIA PRO 5.5.0 — NativeGate
 * Anti-debug / anti-hook gate, pure JVM.
 * Threshold loosened: Reark stub loader adds ~200ms at startup.
 */
object NativeGate {

    /** Set true after successful OTP unlock — skips timing loop for tool calls */
    @Volatile var sessionUnlocked: Boolean = false

    fun preCheck(): Boolean {
        // After a successful OTP session, skip the heavy timing check.
        // The timing check is still enforced on first unlock path.
        if (sessionUnlocked) {
            if (tracerPidNonZero()) return false
            if (stackTainted()) return false
            return true
        }
        if (!timingCheck()) return false
        if (tracerPidNonZero()) return false
        if (stackTainted()) return false
        return true
    }

    /**
     * Timing: threshold 2000ms — generous enough for Reark stub overhead.
     * A real single-step debugger inflates this 50-100x (10s+).
     */
    private fun timingCheck(): Boolean {
        val t0 = System.nanoTime()
        var acc = 0L
        for (i in 0 until 100_000) acc += i.toLong()
        val elapsed = System.nanoTime() - t0
        if (acc == -1L) return false
        return elapsed < 2_000_000_000L  // 2 seconds
    }

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
            ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
    } catch (_: Exception) { 0 }

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

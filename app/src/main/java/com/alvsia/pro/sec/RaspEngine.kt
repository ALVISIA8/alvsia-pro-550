package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Handler
import android.os.Looper
import com.alvsia.pro.tool.RamToolVault
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Grade-A layered RASP (Kotlin + native librasp_guard).
 * Hard-block session only on instrumentation (Frida/debugger/hook).
 * Root/emulator -> report + degrade, tools may still run (member devices often rooted).
 */
object RaspEngine {
    private val started = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    @Volatile var threatLevel: Int = 0
        private set

    fun start(ctx: Context, license: String = "") {
        if (!started.compareAndSet(false, true)) return
        val app = ctx.applicationContext
        try {
            // securevale init if on classpath
            Class.forName("com.securevale.rasp.android.SecureApp")
                .getMethod("init")
                .invoke(null)
        } catch (_: Throwable) {
        }
        tick(app, license)
        handler.postDelayed(object : Runnable {
            override fun run() {
                tick(app, license)
                handler.postDelayed(this, 12_000L)
            }
        }, 12_000L)
    }

    fun tick(ctx: Context, license: String = "") {
        val reasons = mutableListOf<String>()
        try {
            if (Debug.isDebuggerConnected()) reasons += "debugger"
            if (Debug.waitingForDebugger()) reasons += "wait_debugger"
        } catch (_: Exception) {
        }
        reasons += FridaProbe.signals()
        reasons += EnvProbe.signals(ctx)
        reasons += emulatorSignals()
        val tamper = Tamper.evaluate(ctx)
        if (!tamper.ok) reasons += tamper.reasons.map { "tamper:$it" }
        reasons += NativeGuard.flagsToReasons(NativeGuard.scanFlags())
        if (reasons.isEmpty()) return

        threatLevel = reasons.size.coerceAtMost(10)
        Guard.degraded = true
        ThreatReport.emit(ctx, "RASP", reasons.distinct().joinToString("|"), license)

        val hard = reasons.any {
            it.contains("frida", true) || it.contains("debugger") ||
                it.contains("maps") || it.contains("tracer") ||
                it.contains("hook") || it.contains("gadget") ||
                it.contains("sig_mismatch")
        }
        // Always wipe RAM tool cache on any threat signal
        RamToolVault.wipeAll()
        if (hard) {
            SessionGate.onThreat()
        }
    }

    private fun emulatorSignals(): List<String> {
        val r = mutableListOf<String>()
        try {
            val f = Build.FINGERPRINT
            if (f.startsWith("generic") || f.contains("emulator") || f.contains("vbox")) r += "emu_fp"
            if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) r += "emu_model"
            if (Build.MANUFACTURER.contains("Genymotion", true)) r += "emu_geny"
            if (Build.PRODUCT.contains("sdk") || Build.PRODUCT.contains("vbox")) r += "emu_product"
        } catch (_: Exception) {
        }
        return r
    }
}

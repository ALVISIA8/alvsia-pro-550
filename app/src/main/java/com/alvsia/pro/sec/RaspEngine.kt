package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Handler
import android.os.Looper
import com.alvsia.pro.tool.RamToolVault
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * ALVISIA PRO 5.5.0 — RaspEngine HARDENED (Enterprise-Grade RASP)
 *
 * Detection matrix (all regions — China / Russia / USA / Israel / Enterprise):
 *  ① Debugger (JDWP + waitingForDebugger + TracerPid)
 *  ② Frida / Xposed / Substrate / Dobby / ShadowHook / bhook (FridaProbe)
 *  ③ Memory dump attempt — /proc/self/mem open by foreign pid (MemoryGuard)
 *  ④ Root / su / Magisk / KernelSU (EnvProbe)
 *  ⑤ Emulator / VM / QEMU / VBox / BlueStacks / Genymotion (EnvProbe + own)
 *  ⑥ Clone / VirtualApp / BlackBox / parallel space (EnvProbe)
 *  ⑦ APK certificate mismatch / repack / extra DEX (IntegrityBomb)
 *  ⑧ MITM / proxy / VPN active (NetworkGuard)
 *  ⑨ ADB enabled + adb root shell (EnvProbe)
 *  ⑩ Hook packages installed (FridaProbe.hasHookPackage)
 *
 * Hard-kill (session lock + RAM wipe):
 *   ① ② ③ ⑦ — instrumentation and repack are always hard.
 *
 * Soft (degrade + report):
 *   ④ ⑤ ⑥ ⑧ ⑨ ⑩ — rooted/emulated devices often belong to legitimate testers.
 *
 * Tick interval: 8 s (faster than original 12 s).
 */
object RaspEngine {

    private val started = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private val hardKillCount = AtomicInteger(0)

    @Volatile var threatLevel: Int = 0
        private set

    // ── Public API ────────────────────────────────────────────────────

    fun start(ctx: Context, license: String = "") {
        if (!started.compareAndSet(false, true)) return
        val app = ctx.applicationContext

        // Native RASP remains active without the optional third-party SDK.
        // First tick immediately
        tick(app, license)

        // Background ticks every 8 s
        handler.postDelayed(object : Runnable {
            override fun run() {
                tick(app, license)
                handler.postDelayed(this, 8_000L)
            }
        }, 8_000L)

        // Additional: deep scan every 60 s (memory + network — heavier ops)
        handler.postDelayed(object : Runnable {
            override fun run() {
                deepTick(app, license)
                handler.postDelayed(this, 60_000L)
            }
        }, 60_000L)
    }

    fun tick(ctx: Context, license: String = "") {
        val hard = mutableListOf<String>()
        val soft = mutableListOf<String>()

        // ① Debugger
        try {
            if (Debug.isDebuggerConnected()) hard += "debugger"
            if (Debug.waitingForDebugger()) hard += "wait_debugger"
        } catch (_: Exception) {}

        // ② Frida / hooks — trigger async port scan refresh before reading signals
        FridaProbe.refreshPortScanAsync()
        val fridaHits = FridaProbe.signals()
        hard += fridaHits
        hard += NativeGuard.flagsToReasons(NativeGuard.scanFlags())

        // ③ TracerPid
        MemoryGuard.detectPtrace()?.let { hard += it }

        // ④ Root / su
        val envSigs = EnvProbe.signals(ctx)
        val rootSigs = envSigs.filter {
            it.startsWith("su_") || it.startsWith("root_") || it == "test_keys"
                    || it.startsWith("prop_") || it == "adb_root_shell"
        }
        soft += rootSigs

        // ⑤ Emulator / VM
        val emuSigs = envSigs.filter {
            it.startsWith("emulator") || it.startsWith("emu_") || it.startsWith("qemu")
                    || it.startsWith("vbox") || it == "hypervisor_cpu"
        }
        soft += emuSigs

        // ⑥ Clone
        val cloneSigs = envSigs.filter {
            it.startsWith("clone") || it.startsWith("work_profile") || it.startsWith("virtual_app")
        }
        soft += cloneSigs

        // ⑦ Integrity
        val bomb = IntegrityBomb.evaluate(ctx)
        if (!bomb.clean) {
            val iHard = bomb.reasons.filter {
                it.startsWith("cert_") || it.startsWith("dex_") || it == "clone_container"
            }
            val iSoft = bomb.reasons - iHard.toSet()
            hard += iHard.map { "integrity:$it" }
            soft += iSoft.map { "integrity:$it" }
        }

        // ⑧ ADB
        val adbSigs = envSigs.filter { it.startsWith("adb") }
        soft += adbSigs

        // ⑩ Hook packages
        try {
            val hookPkgs = FridaProbe.hasHookPackage(ctx.packageManager)
            soft += hookPkgs
        } catch (_: Exception) {}

        // ── Evaluate ──────────────────────────────────────────────────

        val allSignals = (hard + soft).distinct()
        if (allSignals.isEmpty()) {
            threatLevel = 0
            return
        }

        threatLevel = allSignals.size.coerceAtMost(10)
        Guard.degraded = true

        val detail = "hard=[${hard.joinToString("|")}] soft=[${soft.joinToString("|")}]"
        ThreatReport.emit(ctx, "RASP_TICK", detail, license)

        if (hard.isNotEmpty()) {
            RamToolVault.wipeAll()
            val killCount = hardKillCount.incrementAndGet()
            // On repeated hard kills, crash the process to prevent bypass loops
            if (killCount >= 3) {
                ThreatReport.emit(ctx, "RASP_PROCESS_EXIT", "repeated_hard:$killCount", license)
                android.os.Process.killProcess(android.os.Process.myPid())
            }
            SessionGate.onThreat()
        }
    }

    // ── Deep scan (memory + network — run less frequently) ───────────

    private fun deepTick(ctx: Context, license: String = "") {
        thread(name = "rasp-deep", isDaemon = true) {
            val r = mutableListOf<String>()

            // Memory dump detection
            r += MemoryGuard.allSignals()

            // Network / MITM
            r += NetworkGuard.signals(ctx)

            if (r.isNotEmpty()) {
                threatLevel = (threatLevel + r.size).coerceAtMost(10)
                Guard.degraded = true
                ThreatReport.emit(ctx, "RASP_DEEP", r.joinToString("|"), license)

                val hardDeep = r.filter {
                    it.startsWith("mem_open") || it.startsWith("pagemap") ||
                            it.startsWith("dump_proc") || it.startsWith("ptrace")
                }
                if (hardDeep.isNotEmpty()) {
                    RamToolVault.wipeAll()
                    SessionGate.onThreat()
                }
            }
        }
    }

    // ── Emulator signals (kept for RaspEngine self-use) ──────────────

    private fun emulatorSignals(): List<String> {
        val r = mutableListOf<String>()
        try {
            val fp = Build.FINGERPRINT
            if (fp.startsWith("generic") || fp.contains("emulator") || fp.contains("vbox")) r += "emu_fp"
            if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) r += "emu_model"
            if (Build.MANUFACTURER.contains("Genymotion", true)) r += "emu_geny"
            if (Build.PRODUCT.contains("sdk") || Build.PRODUCT.contains("vbox")) r += "emu_product"
        } catch (_: Exception) {}
        return r
    }

}

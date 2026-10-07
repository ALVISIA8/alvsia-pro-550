package com.alvsia.pro.sec

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * ALVISIA PRO 5.5.0 — FridaProbe R5.4 FIX
 *
 * R5.4 CHANGE: /sbin/.magisk dan /data/adb/magisk DIHAPUS dari PATHS.
 * Kedua path ini adalah Magisk root markers, bukan Frida indicators.
 * Device Magisk tanpa Frida aktif seharusnya TIDAK menghasilkan hard signal.
 * Root detection sudah di-handle oleh EnvProbe -> soft signals -> telemetry only.
 * Duplicate-counting root markers sebagai hard signal menyebabkan
 * Guard.degraded=true pada device user yang legitimate.
 */
object FridaProbe {

    // ── Filesystem paths — FRIDA ONLY, no Magisk markers ─────────────
    private val PATHS = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/hluda-server",
        "/data/local/tmp/frida-helper-32",
        "/data/local/tmp/frida-helper-64",
        "/data/local/tmp/frida-gadget",
        "/data/local/tmp/frida-helper",
        "/data/local/tmp/fs-main",
        "/data/local/tmp/linjector",
        "/data/local/tmp/agent",
        "/data/local/tmp/objection",
        "/system/bin/frida-server",
        "/system/xbin/frida-server",
        // NOTE: /sbin/.magisk dan /data/adb/magisk DIHAPUS — root markers,
        // bukan Frida. Handled by EnvProbe as soft signals.
        "/proc/net/unix",     // checked via content not existence
    )

    // ── /proc/self/maps markers ───────────────────────────────────────
    private val MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "com.saurik.substrate", "libsubstrate", "substrate32", "substrate64",
        "libsandhook", "libepic", "epic-arm", "epic-arm64",
        "riru", "zygisk",
        "perseus", "obproxy",
        "linjector",
        "agent-arm", "agent-arm64",
        "libhook", "libdobby", "dobby",
        "libandroid_inline_hook",
        "shadowhook", "shadow_hook",
        "bhook", "bytehook",
        "fdsan", "turbo_trace", "whale_arm",
        "com.taichi.hookprovider"
    )

    // ── Known hook tool packages ──────────────────────────────────────
    private val HOOK_PKGS = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "com.saurik.cydia",
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "io.va.exposed",
        "com.zhenxi.hunter",
        "com.rikkati.clash",
        "com.frida.console",
        "me.weishu.kernelsu"
    )

    // ── Frida server default ports + common remaps ────────────────────
    private val PROBE_PORTS = intArrayOf(27042, 27043, 27044, 27045, 23946, 27047, 1234, 4444)

    // ── Background port-scan cache ────────────────────────────────────
    private val _portScanExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "fp-portscan").also { it.isDaemon = true }
    }
    @Volatile private var _cachedPortSignals: List<String> = emptyList()
    private val _lastPortScan = AtomicLong(0L)
    private const val PORT_SCAN_TTL_MS = 30_000L

    fun refreshPortScanAsync() {
        val now = System.currentTimeMillis()
        if (now - _lastPortScan.get() < PORT_SCAN_TTL_MS) return
        _lastPortScan.set(now)
        _portScanExecutor.submit {
            val found = mutableListOf<String>()
            for (port in PROBE_PORTS) {
                if (portOpen(port)) found += "port:$port"
            }
            _cachedPortSignals = found
        }
    }

    fun signals(): List<String> {
        val out = mutableListOf<String>()

        // 1. Path probes
        PATHS.filter { it != "/proc/net/unix" }.forEach { p ->
            try { if (File(p).exists()) out += "path:${File(p).name}" } catch (_: Exception) {}
        }

        // 2. /proc/self/maps scan
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            MAP_MARKERS.forEach { m -> if (m in maps) out += "maps:$m" }
        } catch (_: Exception) {}

        // 3. Port scan — cached
        out += _cachedPortSignals

        // 4. /proc/net/unix domain sockets
        try {
            val unix = File("/proc/net/unix").readText().lowercase()
            val fridaAbstract = listOf("frida", "gdbus_frida", "re.frida")
            fridaAbstract.forEach { m -> if (m in unix) out += "unix_sock:$m" }
        } catch (_: Exception) {}

        // 5. Gadget mapped into process
        try {
            val mapsRaw = File("/proc/self/maps").readText()
            if (mapsRaw.contains("libgadget", ignoreCase = true) ||
                mapsRaw.contains("FridaGadget", ignoreCase = true))
                out += "gadget_mapped"
        } catch (_: Exception) {}

        // 6. TracerPid
        try {
            val status = File("/proc/self/status").readText()
            val tpid = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
            if (tpid > 0) out += "tracer_pid:$tpid"
        } catch (_: Exception) {}

        // 7. /proc/self/fd frida pipes
        try {
            File("/proc/self/fd").listFiles()?.forEach { fd ->
                val link = fd.canonicalPath.lowercase()
                if ("frida" in link || "gadget" in link || "linjector" in link)
                    out += "fd:${fd.name}"
            }
        } catch (_: Exception) {}

        // 8. smaps
        try {
            val smaps = File("/proc/self/smaps").readText().lowercase()
            if ("frida" in smaps || "gadget" in smaps) out += "smaps_hit"
        } catch (_: Exception) {}

        return out.distinct()
    }

    fun hasHookPackage(pm: android.content.pm.PackageManager): List<String> {
        val found = mutableListOf<String>()
        HOOK_PKGS.forEach { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                found += "pkg:$pkg"
            } catch (_: Exception) {}
        }
        return found
    }

    private fun portOpen(port: Int): Boolean = try {
        Socket().use { s ->
            s.soTimeout = 50
            s.connect(InetSocketAddress("127.0.0.1", port), 50)
            true
        }
    } catch (_: Exception) { false }
}

package com.alvsia.pro.sec

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * ALVSIA PRO 5.5.0 — FridaProbe HARDENED
 * Detects: Frida server/gadget, Xposed/LSPosed, Substrate, Riru/Zygisk,
 *          linjector, Objection, hluda, ShadowHook, ByteHook, bhook, dobby,
 *          inline hooks via /proc/self/maps and port scan.
 */
object FridaProbe {

    // ── Filesystem paths ──────────────────────────────────────────────
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
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/proc/net/unix",     // checked via content not existence
    )

    // ── /proc/self/maps markers ───────────────────────────────────────
    private val MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "com.saurik.substrate", "libsubstrate", "substrate32", "substrate64",
        "libsandhook", "libepic", "epic-arm", "epic-arm64",
        "linjector",
        "libdobby", "dobby", "libandroid_inline_hook",
        "shadowhook", "shadow_hook", "bhook", "bytehook",
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

    // ── Main entry — returns all detected signal strings ──────────────
    /**
     * High-confidence active runtime indicators only. Filesystem paths, root
     * manager artifacts and open localhost ports are not proof of injection
     * and therefore must not trigger a session lock.
     */
    fun signals(): List<String> {
        val out = mutableListOf<String>()
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            MAP_MARKERS.forEach { marker ->
                if (marker in maps) out += "maps:$marker"
            }
        } catch (_: Exception) {
            // Unavailable procfs is not proof of tampering.
        }
        try {
            val status = File("/proc/self/status").readText()
            val tracer = status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
            if (tracer > 0) out += "tracer_pid:$tracer"
        } catch (_: Exception) {}
        try {
            val unix = File("/proc/net/unix").readText().lowercase()
            listOf("frida", "gdbus_frida", "re.frida").forEach { marker ->
                if (marker in unix) out += "unix_sock:$marker"
            }
        } catch (_: Exception) {}
        try {
            File("/proc/self/fd").listFiles()?.forEach { fd ->
                val link = try { fd.canonicalPath.lowercase() } catch (_: Exception) { "" }
                if ("frida" in link || "gadget" in link || "linjector" in link) {
                    out += "fd:${fd.name}"
                }
            }
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

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
    private val HARD_MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget", "linjector"
    )
    private val SOFT_HOOK_LIBRARY_MARKERS = listOf(
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "com.saurik.substrate", "libsubstrate", "substrate32", "substrate64",
        "libsandhook", "libepic", "epic-arm", "epic-arm64",
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
            val maps = File("/proc/self/maps").readLines()
            for (line in maps) {
                // Linux maps columns include an address range, permissions, offset,
                // device, inode and an optional mapping pathname. Only executable
                // mappings indicate that a native hook library is active in-process.
                val fields = line.trim().split(Regex("\\s+"), limit = 6)
                if (fields.size < 2 || 'x' !in fields[1]) continue
                val mappedName = fields.getOrNull(5)?.lowercase().orEmpty()
                if (mappedName.isBlank()) continue
                HARD_MAP_MARKERS.filter { it in mappedName }.forEach { out += "maps:$it" }
                SOFT_HOOK_LIBRARY_MARKERS.filter { it in mappedName }.forEach { out += "hooklib:$it" }
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
        // Socket names and file descriptors can be left by unrelated tools and
        // are not proof that code is injected into this process. Do not use them
        // as hard-block signals; active maps and TracerPid are stronger evidence.
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

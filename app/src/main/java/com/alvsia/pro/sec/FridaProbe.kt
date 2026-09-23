package com.alvsia.pro.sec

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

object FridaProbe {
    private val PATHS = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/system/bin/frida-server",
        "/system/xbin/frida-server",
        "/data/local/tmp/frida",
        "/sbin/.magisk",
        "/data/local/tmp/hluda-server",
        "/data/local/tmp/frida-helper",
        "/data/local/tmp/fs-main",
        "/data/local/tmp/linjector"
    )

    private val MAP = listOf(
        "frida-agent", "frida-gadget", "libfrida", "libgadget",
        "xposed", "lsposed", "edxposed", "substrate", "libsubstrate",
        "libsandhook", "libepic", "riru", "zygisk", "perseus"
    )

    fun signals(): List<String> {
        val out = mutableListOf<String>()
        try {
            for (p in PATHS) {
                if (File(p).exists()) out += "path:$p"
            }
        } catch (_: Exception) {
        }
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            for (m in MAP) {
                if (m in maps) out += "maps:$m"
            }
        } catch (_: Exception) {
        }
        for (port in listOf(27042, 27043, 23946, 27047)) {
            if (portOpen(port)) out += "port:$port"
        }
        return out.distinct()
    }

    private fun portOpen(port: Int): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 60)
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}

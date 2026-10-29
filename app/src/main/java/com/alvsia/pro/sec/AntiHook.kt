package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * ALVISIA PRO 5.5.1 — AntiHook (Sprint 1 — Layer 2: Anti-Hook)
 *
 * Detects:
 *  • Xposed framework (de.robv.android.xposed.installer)
 *  • LSPosed (org.lsposed.manager)
 *  • EdXposed (io.va.exposed, io.github.lsposed)
 *  • Substrate (com.saurik.cydia, com.saurik.substrate)
 *  • TaiChi (com.taichi.hookprovider)
 *  • SandHook / EpicHook / Whale / Riru / Zygisk via /proc/self/maps
 *  • VirtualApp / Parallel Space clone environments via /proc/self/cgroup
 *
 * Reference patterns:
 *  - sebacipolat/WolfGuard (JNI prologue integrity)
 *  - securevale/android-rasp (hook framework package detection)
 *  - talsec/Free-RASP-Android (similar Xposed/Substrate detection list)
 */
object AntiHook {

    /**
     * Known hook framework packages. Presence of any = strong evidence of
     * hook framework installation on the device. This is NOT proof of active
     * injection into our process — but a high-confidence soft signal.
     */
    private val HOOK_FRAMEWORK_PACKAGES = listOf(
        // Xposed family
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "org.lsposed.lspatch",
        "io.va.exposed",
        "org.meowcat.edxposed.manager",
        // Substrate family
        "com.saurik.cydia",
        "com.saurik.substrate",
        // Hook toolkits
        "com.taichi.hookprovider",
        "com.taichi.app",
        "com.android.taichi",
        // Frida consoles (sandbox-side)
        "com.frida.console",
        "re.frida.server",
        // Magisk modules
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        // Other root/hook helpers
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.kingouser.com",
        "com.kingroot.kinguser",
        // Riru/Zygisk detectable companion apps
        "org.riru.management",
        "com.zhenxi.hunter"
    )

    /**
     * /proc/self/maps markers for hook libraries injected into our process.
     * These are STRONG signals — the lib is loaded into OUR address space.
     */
    private val HARD_MAP_MARKERS = listOf(
        "frida-agent", "frida-gadget", "frida_agent", "frida_gadget",
        "libfrida", "libgadget", "linjector"
    )
    private val SOFT_HOOK_LIBRARY_MARKERS = listOf(
        "xposed", "lsposed", "edxposed", "de.robv.android.xposed",
        "libxposed_art", "libxposed",
        "com.saurik.substrate", "libsubstrate", "substrate32", "substrate64",
        "libsubstrate-dvm", "libsubstrate-art",
        "libsandhook", "libepic", "epic-arm", "epic-arm64",
        "libdobby", "dobby", "libandroid_inline_hook",
        "shadowhook", "shadow_hook", "bhook", "bytehook", "libbytehook",
        "libwhale", "riru", "zygisk", "libnative_hook",
        "com.taichi.hookprovider", "libvirtual", "libhookprovider"
    )
    private val MAP_MARKERS = HARD_MAP_MARKERS + SOFT_HOOK_LIBRARY_MARKERS

    /**
     * /proc/self/cgroup virtualization markers — VirtualApp, Parallel Space,
     * DualSpace, MultiSpace and similar app-isolation sandboxes leave these
     * signatures in cgroup paths.
     */
    private val CGROUP_VIRTUAL_MARKERS = listOf(
        "/virtual", "/virtualapp", "/parallelspace",
        "/dualspace", "/multispace", "/isolate",
        "/sandbox", "/clone"
    )

    /**
     * /proc/cpuinfo emulator markers — QEMU, VirtualBox, BlueStacks leave
     * recognizable strings in cpuinfo.
     */
    private val CPUINFO_EMULATOR_MARKERS = listOf(
        "qemu", "virtualbox", "bluestacks",
        "genymotion", "nox", "ldplayer",
        "x86", "kvm", "android-x86"
    )

    data class HookReport(
        val clean: Boolean,
        val signals: List<String>
    )

    /**
     * Main entry: scan for active hook frameworks.
     * Returns a list of detected signal strings. Empty list = clean.
     */
    fun signals(): List<String> {
        val out = mutableListOf<String>()
        out.addAll(scanProcMaps())
        out.addAll(scanCgroup())
        out.addAll(scanCpuinfo())
        return out.distinct()
    }

    /**
     * Check for installed hook framework packages (NOT active injection —
     * just presence of the installer app). Soft signal.
     */
    fun hasHookFrameworkPackages(pm: PackageManager): List<String> {
        val found = mutableListOf<String>()
        HOOK_FRAMEWORK_PACKAGES.forEach { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                found += "pkg:$pkg"
            } catch (_: Exception) {
                // not installed — expected
            }
        }
        return found
    }

    /**
     * Scan /proc/self/maps for known hook library markers.
     * Active maps presence = STRONG evidence of injection.
     */
    private fun scanProcMaps(): List<String> {
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
            // /proc unavailable — not proof of tampering
        }
        return out
    }

    /**
     * Scan /proc/self/cgroup for virtualization markers (VirtualApp etc.).
     */
    private fun scanCgroup(): List<String> {
        val out = mutableListOf<String>()
        try {
            val cgroup = File("/proc/self/cgroup").readText().lowercase()
            CGROUP_VIRTUAL_MARKERS.forEach { marker ->
                if (marker in cgroup) out += "cgroup:$marker"
            }
        } catch (_: Exception) {
            // not available on all kernels — soft signal only
        }
        return out
    }

    /**
     * Scan /proc/cpuinfo for emulator markers.
     * Note: this is a soft signal — some real ARM devices have x86 strings
     * in cpuinfo for compatibility layers. Treat as soft warn only.
     */
    private fun scanCpuinfo(): List<String> {
        val out = mutableListOf<String>()
        try {
            val cpuinfo = File("/proc/cpuinfo").readText().lowercase()
            CPUINFO_EMULATOR_MARKERS.forEach { marker ->
                if (marker in cpuinfo) out += "cpuinfo:$marker"
            }
        } catch (_: Exception) {
            // not available — skip
        }
        return out
    }

    /**
     * Quick boolean: is any STRONG signal present? (active injection via maps)
     */
    fun isHardHookPresent(): Boolean {
        return scanProcMaps().any { it.startsWith("maps:") }
    }

    /**
     * Quick boolean: is the device running in a virtualized sandbox?
     */
    fun isVirtualEnvironment(): Boolean {
        return scanCgroup().isNotEmpty()
    }
}

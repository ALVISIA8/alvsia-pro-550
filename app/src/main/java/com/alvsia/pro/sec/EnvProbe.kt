package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * ALVISIA PRO 5.5.0 — EnvProbe HARDENED
 * Root · emulator · VM · clone · virtual space · test build · adb · work profile
 */
object EnvProbe {

    // ── Su binary locations ───────────────────────────────────────────
    private val SU_PATHS = listOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/su", "/data/adb/su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/KernelSU.apk",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/dev/.su_info",
        "/proc/1/ns/mnt",   // mount ns check via existence
    )

    // ── Emulator / VM build string fragments ─────────────────────────
    private val EMU_STRINGS = listOf(
        "generic", "emulator", "android sdk", "sdk_gphone",
        "google_sdk", "droid4x", "nox", "bluestacks", "bluestacks2",
        "genymotion", "vbox", "goldfish", "ranchu", "ttvm",
        "andy", "mumu", "ldplayer", "memu", "windroye",
        "iemu", "xpen", "youwave", "leapdroid",
        "phoenix", "shiftone", "samsungrobotium"
    )

    // ── Props that differ on real devices ─────────────────────────────
    private val EMU_HW = listOf("goldfish", "ranchu", "vbox86", "nox")

    // ── Clone / Dual / Virtual space data dir fragments ───────────────
    private val CLONE_FRAGS = listOf(
        "parallel", "cloner", "dual", "island", "shelter", "clone",
        "dualspace", "multispace", "2accounts", "twinmate",
        "virtualapp", "black_box", "blackbox", "vmos",
        "vboxmanager", "vspace", "virtualxposed"
    )

    // ── Root manager / tool packages ─────────────────────────────────
    private val ROOT_PKGS = listOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu",
        "com.noshufou.android.su", "com.koushikdutta.superuser",
        "me.weishu.kernelsu", "com.banka.su",
        "com.kingoapp.root", "com.iroot.iroot",
        "com.joeykrim.rootcheck", "com.thirdparty.superuser",
        "com.amphoras.hidemyroot", "com.formyhm.hideroot",
        "stericson.busybox", "com.busybox.android",
        "com.zachspong.temprootremovejb"
    )

    fun signals(ctx: Context): List<String> {
        val r = mutableListOf<String>()

        // 1. Su binary paths
        if (SU_PATHS.any { File(it).exists() }) r += "su_path"

        // 2. Su command execution
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val out = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (out.isNotEmpty()) r += "su_which"
        } catch (_: Exception) {}

        // 3. Build tag test-keys
        try {
            if (Build.TAGS?.contains("test-keys") == true) r += "test_keys"
        } catch (_: Exception) {}

        // 4. System properties via Runtime (getprop)
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", "ro.build.type"))
            val v = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (v == "userdebug" || v == "eng") r += "prop_buildtype:$v"
        } catch (_: Exception) {}
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", "ro.debuggable"))
            val v = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (v == "1") r += "prop_debuggable"
        } catch (_: Exception) {}
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", "ro.secure"))
            val v = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (v == "0") r += "prop_insecure"
        } catch (_: Exception) {}

        // 5. Build fingerprint / model / hw strings
        val fp = listOf(
            Build.FINGERPRINT, Build.MODEL, Build.MANUFACTURER,
            Build.BRAND, Build.DEVICE, Build.PRODUCT, Build.HARDWARE
        ).joinToString("|").lowercase()
        if (EMU_STRINGS.any { it in fp }) r += "emulator_fp"
        if (EMU_HW.any { it.equals(Build.HARDWARE, ignoreCase = true) }) r += "emulator_hw"

        // 6. QEMU / VBox devices
        if (File("/dev/socket/qemud").exists() || File("/dev/qemu_pipe").exists()) r += "qemu_dev"
        if (File("/dev/vboxguest").exists() || File("/dev/vboxuser").exists()) r += "vbox_dev"

        // 7. CPU features — emulators often lack specific CPU ABI entries
        try {
            val cpuinfo = File("/proc/cpuinfo").readText().lowercase()
            if ("hypervisor" in cpuinfo || "vmx" in cpuinfo) r += "hypervisor_cpu"
        } catch (_: Exception) {}

        // 8. Root manager packages
        try {
            ROOT_PKGS.forEach { pkg ->
                try {
                    ctx.packageManager.getPackageInfo(pkg, 0)
                    r += "root_pkg:${pkg.substringAfterLast(".")}"
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        // 9. Magisk hide bypass check — check if magisk manager is disguised
        try {
            val pm = ctx.packageManager
            val all = pm.getInstalledPackages(0)
            // magisk randomizes package name on some versions — detect by permissions
            all.forEach { pi ->
                if (pi.requestedPermissions?.any { p ->
                        p == "android.permission.ACCESS_SUPERUSER"
                    } == true) {
                    r += "root_perm:${pi.packageName}"
                }
            }
        } catch (_: Exception) {}

        // 10. Clone / VirtualApp data dir
        try {
            val data = ctx.applicationInfo.dataDir ?: ""
            if (CLONE_FRAGS.any { it in data.lowercase() }) r += "clone_path"
            // Multi-user IDs > 0 often indicate work profile or VirtualApp
            if (data.matches(Regex(".*/user/[1-9]\\d*.*"))) r += "work_profile"
        } catch (_: Exception) {}

        // 11. VirtualApp / BlackBox file probe
        val vaPaths = listOf(
            "/data/data/io.va.exposed",
            "/data/data/com.lody.virtual",
            "/data/data/com.microsoft.intune.mam",
        )
        if (vaPaths.any { File(it).exists() }) r += "virtual_app_data"

        // 12. ADB enabled via Settings (requires READ_SECURE_SETTINGS or shell)
        try {
            val adb = android.provider.Settings.Global.getInt(
                ctx.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED, 0
            )
            if (adb == 1) r += "adb_enabled"
        } catch (_: Exception) {}

        // 13. USB debugging + rooted adb
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("id"))
            val out = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if ("uid=0" in out) r += "adb_root_shell"
        } catch (_: Exception) {}

        return r.distinct()
    }

    fun report(ctx: Context, license: String = "") {
        val s = signals(ctx)
        if (s.isNotEmpty()) ThreatReport.emit(ctx, "ENV_HINT", s.joinToString("|"), license)
    }
}

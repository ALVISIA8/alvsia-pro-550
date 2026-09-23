package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import java.io.File

object EnvProbe {
    fun signals(ctx: Context): List<String> {
        val r = mutableListOf<String>()
        val roots = listOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su"
        )
        if (roots.any { File(it).exists() }) r += "su_path"
        try {
            if (Build.TAGS?.contains("test-keys") == true) r += "test_keys"
        } catch (_: Exception) {
        }
        try {
            if (ctx.packageManager.getLaunchIntentForPackage("com.topjohnwu.magisk") != null) {
                r += "magisk_pkg"
            }
        } catch (_: Exception) {
        }
        // Emulator / virtualization
        try {
            val fp = listOf(
                Build.FINGERPRINT, Build.MODEL, Build.MANUFACTURER, Build.BRAND,
                Build.DEVICE, Build.PRODUCT, Build.HARDWARE
            ).joinToString("|").lowercase()
            val emu = listOf(
                "generic", "emulator", "android sdk", "sdk_gphone", "google_sdk",
                "droid4x", "nox", "bluestacks", "genymotion", "vbox", "goldfish",
                "ranchu", "ttvm", "andy", "mumu", "ldplayer", "memu"
            )
            if (emu.any { it in fp }) r += "emulator_fp"
            if (Build.HARDWARE.equals("goldfish", true) || Build.HARDWARE.equals("ranchu", true)) {
                r += "emulator_hw"
            }
            if (File("/dev/socket/qemud").exists() || File("/dev/qemu_pipe").exists()) {
                r += "qemu_pipe"
            }
        } catch (_: Exception) {
        }
        // Clone / dual apps
        try {
            val data = ctx.applicationInfo.dataDir ?: ""
            val low = data.lowercase()
            if (listOf("parallel", "cloner", "dual", "island", "shelter", "clone").any { it in low }) {
                r += "clone_path"
            }
            // multi-user virtual often uses /data/user/999 or similar non-0
            if (data.contains("/user/999") || data.contains("/user/10")) r += "work_profile_hint"
        } catch (_: Exception) {
        }
        return r.distinct()
    }

    fun report(ctx: Context, license: String = "") {
        val s = signals(ctx)
        if (s.isNotEmpty()) {
            ThreatReport.emit(ctx, "ENV_HINT", s.joinToString("|"), license)
        }
    }
}

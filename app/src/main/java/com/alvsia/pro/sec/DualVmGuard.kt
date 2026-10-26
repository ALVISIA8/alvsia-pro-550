package com.alvsia.pro.sec

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.alvsia.pro.BuildConfig
import java.security.MessageDigest

/**
 * ALVSIA Dual-Layer Runtime Gate (DLRG).
 *
 * Stage A executes a compact, bounded instruction stream in the Kotlin runtime.
 * Stage B independently asks the native RASP layer for instrumentation flags.
 * This is an in-house integrity gate, not a claim of commercial Virbox equivalence.
 */
object DualVmGuard {
    private const val OP_PACKAGE = 0x11
    private const val OP_VERSION = 0x22
    private const val OP_NATIVE = 0x33
    private const val OP_CERT_FORMAT = 0x44

    // Fixed-size program: opcode, opcode, opcode, opcode. Unknown instructions fail closed.
    private val program = byteArrayOf(OP_PACKAGE.toByte(), OP_VERSION.toByte(), OP_NATIVE.toByte(), OP_CERT_FORMAT.toByte())

    fun inspect(context: Context): List<String> {
        val app = context.applicationContext
        val failures = ArrayList<String>(2)
        var pc = 0
        var steps = 0
        while (pc < program.size && steps < 8) {
            val op = program[pc].toInt() and 0xff
            val ok = when (op) {
                OP_PACKAGE -> app.packageName == "com.alvsia.pro"
                OP_VERSION -> BuildConfig.VERSION_CODE >= 97 && Build.VERSION.SDK_INT >= 26
                OP_NATIVE -> BuildConfig.DEBUG || NativeGuard.isNativeLoaded()
                OP_CERT_FORMAT -> validDigest(BuildConfig.CERT_SHA256)
                else -> false
            }
            if (!ok) failures += when (op) {
                OP_PACKAGE -> "dlrg_package_mismatch"
                OP_VERSION -> "dlrg_version_mismatch"
                OP_NATIVE -> "dlrg_native_layer_missing"
                OP_CERT_FORMAT -> "dlrg_cert_config_invalid"
                else -> "dlrg_unknown_opcode"
            }
            pc++
            steps++
        }
        if (pc != program.size || steps != program.size) failures += "dlrg_vm_bounds"
        // Stage B is independent from the Kotlin instruction interpreter.
        if (NativeGuard.isNativeLoaded()) {
            val nativeFlags = try { NativeGuard.scanFlags() } catch (_: Throwable) { -1 }
            if (nativeFlags < 0) failures += "dlrg_native_probe_failed"
            else if (nativeFlags != 0) failures += NativeGuard.flagsToReasons(nativeFlags).map { "dlrg_$it" }
        } else if (!BuildConfig.DEBUG) {
            failures += "dlrg_native_layer_missing"
        }
        return failures.distinct()
    }

    private fun validDigest(value: String): Boolean {
        if (!value.matches(Regex("^[0-9a-fA-F]{64}$"))) return false
        return try { MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).size == 32 }
        catch (_: Throwable) { false }
    }
}

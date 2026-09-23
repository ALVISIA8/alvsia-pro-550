package com.alvsia.pro.sec

/**
 * Stub native guard — no JNI required for release compile stability.
 * Runtime signals still come from Guard / FridaProbe / EnvProbe.
 */
object NativeGuard {
    fun scanFlags(): Int = 0

    fun flagsToReasons(f: Int): List<String> = emptyList()

    fun wipe(buf: ByteArray?) {
        buf?.fill(0)
    }
}

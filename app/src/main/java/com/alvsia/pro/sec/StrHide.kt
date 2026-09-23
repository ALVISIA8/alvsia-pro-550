package com.alvsia.pro.sec

/**
 * Runtime string recovery ? avoids plain constants in simple string tables.
 */
object StrHide {
    fun d(mask: Int, data: IntArray): String {
        val out = ByteArray(data.size)
        for (i in data.indices) {
            out[i] = (data[i] xor mask xor (i and 0x1F)).toByte()
        }
        return String(out, Charsets.UTF_8)
    }
}

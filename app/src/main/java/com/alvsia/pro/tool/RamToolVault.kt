package com.alvsia.pro.tool

import com.alvsia.pro.sec.NativeGuard
import java.util.concurrent.ConcurrentHashMap

/**
 * Panel-delivered tool blobs live only in process memory.
 * On RASP threat -> zero fill via native + clear maps.
 */
object RamToolVault {
    private val map = ConcurrentHashMap<String, ByteArray>()

    fun put(id: String, data: ByteArray) {
        wipeKey(id)
        map[id] = data.copyOf()
    }

    fun get(id: String): ByteArray? = map[id]?.copyOf()

    fun wipeKey(id: String) {
        map.remove(id)?.let { NativeGuard.wipe(it) }
    }

    fun wipeAll() {
        for (k in map.keys().toList()) wipeKey(k)
        map.clear()
    }

    fun size(): Int = map.values.sumOf { it.size }
}

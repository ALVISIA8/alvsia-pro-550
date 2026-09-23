package com.alvsia.pro.tool

import com.alvsia.pro.ui.home.ToolItem
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class OpenedCore(
    val tools: List<ToolItem>,
    val engineBytes: ByteArray?,
    val plainSize: Int
)

object CoreBundle {
    fun open(fetched: ByteArray): OpenedCore {
        val plain = LevelACore.tryDecrypt(fetched) ?: fetched
        // ALVBUNDLE\x01 | cat_len u32 BE | cat | core_len u32 BE | core
        if (plain.size > 12 && plain.copyOfRange(0, 9).toString(Charsets.US_ASCII) == "ALVBUNDLE") {
            try {
                val bb = ByteBuffer.wrap(plain).order(ByteOrder.BIG_ENDIAN)
                bb.position(10) // after ALVBUNDLE + 1 version byte
                val catLen = bb.int
                if (catLen > 0 && catLen < plain.size) {
                    val cat = ByteArray(catLen)
                    bb.get(cat)
                    val coreLen = bb.int
                    val engine = if (coreLen > 0 && bb.remaining() >= coreLen) {
                        ByteArray(coreLen).also { bb.get(it) }
                    } else null
                    return OpenedCore(ToolCatalog.parseCore(cat), engine, plain.size)
                }
            } catch (_: Exception) {
            }
        }
        // pure catalog
        if (plain.size > 8 && plain.copyOfRange(0, 8).toString(Charsets.US_ASCII) == "ALVCAT01") {
            return OpenedCore(ToolCatalog.parseCore(plain), null, plain.size)
        }
        return OpenedCore(ToolCatalog.defaults(), plain, plain.size)
    }
}

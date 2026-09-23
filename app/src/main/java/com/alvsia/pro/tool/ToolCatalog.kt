package com.alvsia.pro.tool

import com.alvsia.pro.ui.home.ToolItem
import org.json.JSONArray
import org.json.JSONObject

/**
 * ALVSIA PRO 4.6 — focused modules (real engine wired in bridge).
 */
object ToolCatalog {
    fun defaults(): List<ToolItem> = listOf(
        ToolItem(1, "PAK Unpack", "Extract · list · info · CSV"),
        ToolItem(2, "PAK Rebuild", "Repack · inject · encrypt · decrypt"),
        ToolItem(3, "PAK Compact", "Delete entry · empty · clean"),
        ToolItem(4, "OBB Tools", "Unzip · rezip · info"),
        ToolItem(5, "LUA Tools", "Unluac · smart · XOR · constants"),
        ToolItem(6, "File Scan", "Strings · hash · report"),
        ToolItem(7, "Workspace", "Clear WORK/OUT"),
        ToolItem(8, "Export Report", "Session / file summary"),
        ToolItem(9, "Rebrand", "ALVSIA PRO auto · manual brand/channel"),
    )

    fun parseCore(bytes: ByteArray?): List<ToolItem> {
        if (bytes == null || bytes.size < 16) return defaults()
        return try {
            val magic = bytes.copyOfRange(0, 8).toString(Charsets.US_ASCII)
            if (magic != "ALVCAT01") return defaults()
            val json = bytes.copyOfRange(8, bytes.size).toString(Charsets.UTF_8)
            val root = JSONObject(json)
            val arr: JSONArray = root.optJSONArray("tools") ?: return defaults()
            val out = ArrayList<ToolItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(
                    ToolItem(
                        id = o.optInt("id", i + 1),
                        title = o.optString("title", "Tool ${i + 1}"),
                        desc = o.optString("desc", "")
                    )
                )
            }
            if (out.isEmpty()) defaults() else out
        } catch (_: Exception) {
            defaults()
        }
    }
}

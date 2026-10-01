package com.alvsia.pro.tool

import com.alvsia.pro.ui.home.ToolItem
import org.json.JSONArray
import org.json.JSONObject

/**
 * ALVSIA PRO 5.5.0 — expanded 17-module catalog.
 * Modules 1-9: original. 10-17: new additions from v5.5.0-upgrade.
 */
object ToolCatalog {
    fun defaults(): List<ToolItem> = listOf(
        // --- ORIGINAL ---
        ToolItem(1,  "PAK Unpack",      "Extract · list · info · CSV"),
        ToolItem(2,  "PAK Rebuild",     "Repack · inject · encrypt · decrypt"),
        ToolItem(3,  "PAK Compact",     "Delete entry · empty · clean"),
        ToolItem(4,  "OBB Tools",       "Unzip · rezip · info"),
        ToolItem(5,  "LUA Tools",       "Detect · analyze · decompile · clean · XOR · constants"),
        ToolItem(6,  "File Scan",       "Strings · hash · report"),
        ToolItem(7,  "Workspace",       "Clear WORK/OUT"),
        ToolItem(8,  "Export Report",   "Session / file summary"),
        ToolItem(9,  "Rebrand",         "ALVSIA PRO auto · manual brand/channel"),
        // --- NEW v5.5.0 ---
        ToolItem(10, "SO Analyzer",     "XOR-brute · URL extract · AES probe · patch binary"),
        ToolItem(11, "Frida Tracer",    "Live hook JNI · libc strstr · URL sniff via device"),
        ToolItem(12, "XOR Suite",       "Single-byte scan · multi-key · LuaS strip · batch"),
        ToolItem(13, "Decrypt Engine",  "AES-CBC/ECB · ZUC · SM4 · SIMPLE1 · auto-detect"),
        ToolItem(14, "PAK Deep",        "AES-SHA1 PAK · Zstd decompress · ZUC-PAK · SM4"),
        ToolItem(15, "String Recover",  "Obfuscated string restore · constant pool dump"),
        ToolItem(16, "Lua Inject",      "Patch lua bytecode · inject hook · mod repack"),
        ToolItem(17, "Anti-RE Audit",   "Detect weak points in target APK · generate report"),
    )

    fun parseCore(bytes: ByteArray?): List<ToolItem> {
        if (bytes == null || bytes.size < 16) return defaults()
        return try {
            val magic = bytes.copyOfRange(0, 8).toString(Charsets.US_ASCII)
            if (magic != "ALVCAT01") return defaults()
            val json = bytes.copyOfRange(8, bytes.size).toString(Charsets.UTF_8)
            val root = JSONObject(json)
            val arr: JSONArray = root.optJSONArray("tools") ?: return defaults()
            val out = ArrayList<ToolItem>(arr.length().coerceAtLeast(defaults().size))
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(ToolItem(
                    id    = o.optInt("id", i + 1),
                    title = o.optString("title", "Tool ${i+1}"),
                    desc  = o.optString("desc", "")
                ))
            }
            if (out.isEmpty()) defaults() else out
        } catch (_: Exception) {
            defaults()
        }
    }
}

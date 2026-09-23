package com.alvsia.pro.tool

data class SubTool(
    val id: String,
    val title: String,
    val desc: String,
    val guide: String,
    val needsFile: Boolean = true
)

object SubMenus {
    fun title(moduleId: Int): String = when (moduleId) {
        1 -> "PAK Unpack"
        2 -> "PAK Rebuild"
        3 -> "PAK Compact"
        4 -> "OBB Tools"
        5 -> "LUA Tools"
        6 -> "File Scan"
        7 -> "Workspace"
        8 -> "Export Report"
        9 -> "Rebrand"
        else -> "Module $moduleId"
    }

    fun forModule(moduleId: Int): List<SubTool> = when (moduleId) {
        1 -> listOf(
            SubTool("pak_full_unpack", "Full Unpack", "Decrypt + extract tree",
                "Select .pak. Output -> Download/ALVSIA/OUT/PAK/<name>/"),
            SubTool("pak_list", "List Index", "All entry paths",
                "Select .pak. List + file under OUT/PAK/"),
            SubTool("pak_info", "Quick Info", "Header size hash",
                "Select .pak. Report -> OUT/PAK/info.txt"),
            SubTool("pak_csv", "Dump CSV", "Export index CSV",
                "Select .pak. CSV -> OUT/PAK/index.csv"),
        )
        2 -> listOf(
            SubTool("pak_repack_full", "Smart Repack", "Inject edited tree",
                "Edit OUT/PAK/<stem>/ then select original .pak"),
            SubTool("pak_inject", "Inject Files", "Merge WORK/MOD",
                "Put files in WORK/MOD matching internal paths"),
            SubTool("pak_encrypt", "Encrypt PAK", "SIMPLE1 whole-file lock",
                "Select .pak -> *_enc.pak"),
            SubTool("pak_decrypt_restore", "Decrypt Restore", "SIMPLE1 unlock",
                "Select locked .pak -> *_dec.pak"),
        )
        3 -> listOf(
            SubTool("pak_delete_entry", "Delete + Compact", "Remove paths",
                "Write paths to WORK/delete_targets.txt then select .pak"),
            SubTool("pak_delete_all", "Empty Compact", "Strip all entries",
                "Select .pak -> valid empty compact"),
        )
        4 -> listOf(
            SubTool("obb_unzip", "Unzip OBB", "Extract zip/obb",
                "Select .obb/.zip -> OUT/OBB/<name>/"),
            SubTool("obb_rezip", "Rezip OBB", "Folder to .obb",
                "Select unpacked folder or original .obb stem tree"),
            SubTool("obb_info", "OBB Info", "Size listing",
                "Select .obb/.zip"),
        )
        5 -> listOf(
            SubTool("lua_decompile", "Smart Decompile", "Unluac + fallback pipeline",
                "Select .luac/.lua/LuaS. ART unluac or strings+constants+xor."),
            SubTool("lua_constants", "Extract Constants", "String/number dump",
                "Select LuaS/bytecode -> OUT/LUA/*_constants.txt"),
            SubTool("lua_xor_crypt", "XOR Layer", "Body XOR try",
                "Select file -> OUT/LUA/*.xor"),
            SubTool("lua_multi_xor", "Multi-XOR Probe", "Common keys scan",
                "Select file -> OUT/LUA/*_xor_*.bin"),
        )
        6 -> listOf(
            SubTool("string_scan", "String Scanner", "ASCII strings",
                "Select any file -> OUT/SCAN/strings.txt"),
            SubTool("hash_scan", "Hash File", "MD5 SHA1 SHA256",
                "Select file -> OUT/SCAN/hash.txt"),
        )
        7 -> listOf(
            SubTool("clear_work", "Clear Workspace", "Wipe WORK + OUT",
                "No file needed", needsFile = false),
        )
        8 -> listOf(
            SubTool("export_report", "File Report", "Info summary",
                "Select .pak or any file"),
        )
        9 -> listOf(
            SubTool("rebrand_auto", "Auto ALVSIA PRO", "Replace known brands",
                "Select .lua / unpacked folder / text file. Default brand=ALVSIA PRO channel=t.me/ALVSIA_PRO"),
            SubTool("rebrand_manual", "Manual Rebrand", "Use WORK/rebrand_config.txt",
                "Edit WORK/rebrand_config.txt (brand= channel= watermark=) then select file/folder"),
            SubTool("rebrand_scan", "Scan Brands", "Detect watermarks only",
                "Select file or folder -> OUT/REBRAND/scan.txt (no write)"),
        )
        else -> emptyList()
    }
}

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
        1  -> "PAK Unpack"
        2  -> "PAK Rebuild"
        3  -> "PAK Compact"
        4  -> "OBB Tools"
        5  -> "LUA Tools"
        6  -> "File Scan"
        7  -> "Workspace"
        8  -> "Export Report"
        9  -> "Rebrand"
        10 -> "SO Analyzer"
        11 -> "Frida Tracer"
        12 -> "XOR Suite"
        13 -> "Decrypt Engine"
        14 -> "PAK Deep"
        15 -> "String Recover"
        16 -> "Lua Inject"
        17 -> "Anti-RE Audit"
        else -> "Module $moduleId"
    }

    fun forModule(moduleId: Int): List<SubTool> = when (moduleId) {

        // ── 1 PAK Unpack ─────────────────────────────────────────────────
        1 -> listOf(
            SubTool("pak_full_unpack",   "Full Unpack",   "Decrypt + extract tree",
                "Select .pak → OUT/PAK/<n>/"),
            SubTool("pak_list",          "List Index",    "All entry paths",
                "Select .pak → index list under OUT/PAK/"),
            SubTool("pak_info",          "Quick Info",    "Header · size · hash",
                "Select .pak → OUT/PAK/info.txt"),
            SubTool("pak_csv",           "Dump CSV",      "Export index CSV",
                "Select .pak → OUT/PAK/index.csv"),
        )

        // ── 2 PAK Rebuild ─────────────────────────────────────────────────
        2 -> listOf(
            SubTool("pak_repack_full",        "Smart Repack",    "Inject edited tree",
                "Edit OUT/PAK/<stem>/ then select original .pak"),
            SubTool("pak_inject",             "Inject Files",    "Merge WORK/MOD",
                "Put files in WORK/MOD matching internal paths"),
            SubTool("pak_encrypt",            "Encrypt PAK",     "SIMPLE1 whole-file lock",
                "Select .pak → *_enc.pak"),
            SubTool("pak_decrypt_restore",    "Decrypt Restore", "SIMPLE1 unlock",
                "Select locked .pak → *_dec.pak"),
        )

        // ── 3 PAK Compact ─────────────────────────────────────────────────
        3 -> listOf(
            SubTool("pak_delete_entry", "Delete + Compact", "Remove paths",
                "Write paths to WORK/delete_targets.txt then select .pak"),
            SubTool("pak_delete_all",   "Empty Compact",    "Strip all entries",
                "Select .pak → valid empty compact"),
        )

        // ── 4 OBB Tools ───────────────────────────────────────────────────
        4 -> listOf(
            SubTool("obb_unzip", "Unzip OBB", "Extract zip/obb",
                "Select .obb/.zip → OUT/OBB/<n>/"),
            SubTool("obb_rezip", "Rezip OBB", "Folder to .obb",
                "Select unpacked folder / original .obb stem tree"),
            SubTool("obb_info",  "OBB Info",  "Size listing",
                "Select .obb/.zip"),
        )

        // ── 5 LUA Tools ───────────────────────────────────────────────────
        5 -> listOf(
            SubTool("lua_decompile",    "Smart Decompile",    "ART UnLuaC + validated fallback",
                "Select .luac/.lua → validated .lua source"),
            SubTool("lua_analyze",      "LUA Analyzer",       "Format + obfuscation analysis",
                "Detect Lua/LuaJIT/source → structured analysis report"),
            SubTool("lua_constants",    "Extract Constants",  "String/constant dump",
                "Select Lua bytecode → OUT/LUA/*_constants.txt"),
            SubTool("lua_clean_source", "Clean Lua Source",   "Safe source cleanup",
                "Select Lua source → OUT/LUA/*_clean.lua"),
            SubTool("lua_xor_crypt",   "XOR Layer",           "Body XOR probe",
                "Select file → OUT/LUA/*.xor"),
            SubTool("lua_multi_xor",   "Multi-XOR Probe",    "Candidate scan",
                "Select file → OUT/LUA/*_xor_*.bin"),
        )

        // ── 6 File Scan ───────────────────────────────────────────────────
        6 -> listOf(
            SubTool("string_scan", "String Scanner", "ASCII strings",
                "Select any file → OUT/SCAN/strings.txt"),
            SubTool("hash_scan",   "Hash File",      "MD5 SHA1 SHA256",
                "Select file → OUT/SCAN/hash.txt"),
        )

        // ── 7 Workspace ───────────────────────────────────────────────────
        7 -> listOf(
            SubTool("clear_work", "Clear Workspace", "Wipe WORK + OUT",
                "No file needed", needsFile = false),
        )

        // ── 8 Export Report ───────────────────────────────────────────────
        8 -> listOf(
            SubTool("export_report", "File Report", "Info summary",
                "Select .pak or any file"),
        )

        // ── 9 Rebrand ─────────────────────────────────────────────────────
        9 -> listOf(
            SubTool("rebrand_auto",   "Auto ALVSIA PRO",   "Replace known brands",
                "Select .lua / unpacked folder / text. brand=ALVSIA PRO channel=t.me/ALVSIA_PRO"),
            SubTool("rebrand_manual", "Manual Rebrand",    "Use WORK/rebrand_config.txt",
                "Edit WORK/rebrand_config.txt (brand= channel= watermark=) then select file/folder"),
            SubTool("rebrand_scan",   "Scan Brands",       "Detect watermarks only",
                "Select file or folder → OUT/REBRAND/scan.txt (no write)"),
        )

        // ── 10 SO Analyzer ────────────────────────────────────────────────
        10 -> listOf(
            SubTool("so_xor_scan",    "XOR Brute-Scan",   "All 256 single-byte keys + URL extract",
                "Select .so / .bin → OUT/SO/xor_results.txt  (shows all decoded URLs per key)"),
            SubTool("so_multi_xor",   "Multi-Byte XOR",   "Custom key list from WORK/xor_keys.txt",
                "One key per line (hex or utf8). Select binary → OUT/SO/multikey_results.txt"),
            SubTool("so_url_dump",    "URL/String Dump",  "Extract plaintext endpoints",
                "Select .so → OUT/SO/urls.txt + strings.txt"),
            SubTool("so_aes_probe",   "AES Key Probe",    "Detect AES-CBC/ECB key candidates",
                "Select .so → OUT/SO/aes_keys.txt  (entropy + pattern scan)"),
            SubTool("so_patch_url",   "Patch Binary URL", "XOR-encode replacement URL at offset",
                "Prepare WORK/patch_config.txt: offset=0x1234 key=0xAB new_url=https://... → patched .so"),
        )

        // ── 11 Frida Tracer ───────────────────────────────────────────────
        11 -> listOf(
            SubTool("frida_jni_hook",  "JNI URL Tracer",  "Hook JNI_NewStringUTF / strstr / sprintf",
                "Requires device with Frida server. Enter package name in WORK/frida_target.txt → OUT/FRIDA/hooked_urls.txt"),
            SubTool("frida_js_dump",   "JS Script Dump",  "Export generated Frida script for manual use",
                "No device needed. Select APK or enter pkg in WORK/frida_target.txt → OUT/FRIDA/hook_script.js"),
            SubTool("frida_spawn",     "Spawn + Trace",   "Launch app under Frida then capture output",
                "Frida server must run on device. WORK/frida_target.txt → OUT/FRIDA/trace.txt"),
        )

        // ── 12 XOR Suite ──────────────────────────────────────────────────
        12 -> listOf(
            SubTool("xor_single_byte", "Single-Byte Scan",  "Try all 256 keys, show readable candidates",
                "Select any binary → OUT/XOR/single_scan.txt  (sorted by readability score)"),
            SubTool("xor_custom_key",  "Custom XOR Key",    "Apply specific key to file",
                "Put key in WORK/xor_key.txt (hex bytes e.g. DEADBEEF). Select file → OUT/XOR/*_xored.*"),
            SubTool("xor_luas_strip",  "LuaS Strip-XOR",   "Strip LuaS header then XOR",
                "Select .luac with XOR-wrapped LuaS → OUT/XOR/*_stripped.lua"),
            SubTool("xor_batch",       "Batch XOR",         "Apply same key to all files in WORK/BATCH/",
                "Drop files in WORK/BATCH/, set WORK/xor_key.txt → OUT/XOR/batch/"),
        )

        // ── 13 Decrypt Engine ─────────────────────────────────────────────
        13 -> listOf(
            SubTool("dec_auto",        "Auto-Detect",       "Try AES-CBC/ECB, ZUC, SM4, SIMPLE1",
                "Select encrypted blob → OUT/DEC/auto_result.bin  (first successful algo wins)"),
            SubTool("dec_aes_cbc",     "AES-CBC Decrypt",   "Key+IV from WORK/aes_config.txt",
                "aes_config.txt: key=<hex32> iv=<hex16>. Select ciphertext → OUT/DEC/*_aes.bin"),
            SubTool("dec_aes_ecb",     "AES-ECB Decrypt",   "Key from WORK/aes_config.txt",
                "aes_config.txt: key=<hex32>. Select ciphertext → OUT/DEC/*_ecb.bin"),
            SubTool("dec_zuc",         "ZUC Stream",        "Key+IV from WORK/zuc_config.txt",
                "zuc_config.txt: key=<hex32> iv=<hex16>. Select ciphertext → OUT/DEC/*_zuc.bin"),
            SubTool("dec_sm4",         "SM4 Block",         "Key from WORK/sm4_config.txt",
                "sm4_config.txt: key=<hex32> mode=CBC|ECB iv=<hex16>. → OUT/DEC/*_sm4.bin"),
            SubTool("dec_simple1",     "SIMPLE1 Restore",   "Alvsia SIMPLE1 reversal",
                "Select SIMPLE1-encrypted .pak or blob → OUT/DEC/*_simple1.bin"),
        )

        // ── 14 PAK Deep ───────────────────────────────────────────────────
        14 -> listOf(
            SubTool("pak_deep_aes",    "AES-SHA1 PAK",      "Decrypt AES-CBC PAK with SHA1-derived key",
                "Key passphrase in WORK/pak_pass.txt. Select .pak → OUT/PAKD/"),
            SubTool("pak_deep_zstd",   "Zstd Decompress",   "Decompress Zstd-compressed entries",
                "Select .pak or raw Zstd blob → OUT/PAKD/*_zstd/"),
            SubTool("pak_deep_zuc",    "ZUC-PAK",           "ZUC stream decrypt then PAK unpack",
                "zuc_config.txt required. Select .pak → OUT/PAKD/*_zuc/"),
            SubTool("pak_deep_sm4",    "SM4-PAK",           "SM4 decrypt then PAK unpack",
                "sm4_config.txt required. Select .pak → OUT/PAKD/*_sm4/"),
            SubTool("pak_deep_auto",   "Deep Auto-Probe",   "Try all encryption combos",
                "Select .pak → OUT/PAKD/probe_report.txt + first successful extract"),
        )

        // ── 15 String Recover ─────────────────────────────────────────────
        15 -> listOf(
            SubTool("str_recover",     "String Restore",    "Reconstruct obfuscated strings from bytecode",
                "Select .luac → OUT/STR/*_strings_recovered.txt"),
            SubTool("str_constant_pool","Constant Pool",    "Full constant pool dump with types",
                "Select .luac → OUT/STR/*_constants_typed.txt"),
            SubTool("str_xref",        "String XRef",       "Cross-reference strings to function names",
                "Select .luac → OUT/STR/*_xref.txt"),
        )

        // ── 16 Lua Inject ─────────────────────────────────────────────────
        16 -> listOf(
            SubTool("lua_patch_byte",  "Patch Bytecode",    "Inject opcode/constant into .luac",
                "Patch spec in WORK/lua_patch.json: {offset, opcode, value}. Select .luac → OUT/LINJ/*_patched.luac"),
            SubTool("lua_inject_hook", "Inject Hook Func",  "Insert hook function into decompiled lua then recompile",
                "Hook code in WORK/lua_hook.lua. Select target .lua → OUT/LINJ/*_hooked.lua"),
            SubTool("lua_mod_repack",  "Mod + Repack PAK",  "Full workflow: decompile → patch → repack",
                "WORK/lua_hook.lua + WORK/pak_pass.txt optional. Select .pak → OUT/LINJ/*_modded.pak"),
        )

        // ── 17 Anti-RE Audit ──────────────────────────────────────────────
        17 -> listOf(
            SubTool("audit_apk",       "APK Audit",         "Scan APK for weak anti-RE posture",
                "Select .apk → OUT/AUDIT/report.txt  (ProGuard gaps, strings, native coverage)"),
            SubTool("audit_lua",       "LUA Audit",         "Find unhashed strings, naked function names",
                "Select .lua / .luac → OUT/AUDIT/lua_report.txt"),
            SubTool("audit_so",        "SO Coverage",       "Check native lib for exported symbols, debug info",
                "Select .so → OUT/AUDIT/so_report.txt"),
        )

        else -> emptyList()
    }
}

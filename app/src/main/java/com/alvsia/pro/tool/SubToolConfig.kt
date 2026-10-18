package com.alvsia.pro.tool

/**
 * ALVISIA PRO 5.5.2 — SubToolConfig (UX Sprint 1)
 *
 * Inline config schema for subtools that previously required manual
 * WORK config-file creation. The ToolWorkspace renders an inline form
 * from this schema, and on RUN writes the config file transparently
 * before invoking the bridge.
 *
 * This eliminates the biggest UX friction point: users no longer need
 * to open a file manager to create xor_key.txt, aes_config.txt, etc.
 */
data class SubToolConfig(
    val field: String,           // logical field name (e.g. "key_hex")
    val label: String,           // UI label (e.g. "Key (hex)")
    val type: ConfigType,        // TEXT, HEX, MULTILINE, FILE_PICK, INT, BOOL
    val hint: String = "",       // placeholder/help text
    val default: String? = null, // default value
    val required: Boolean = true,
    val workFileName: String? = null  // if set, value written to WORK config files
)

enum class ConfigType {
    TEXT,        // free text input
    HEX,         // hexadecimal input (validates 0-9a-fA-F)
    MULTILINE,   // multiline text (for Lua source, etc.)
    FILE_PICK,   // file picker button
    INT,         // integer input
    BOOL          // toggle switch
}

/**
 * Returns the config schema for a subtool, or empty list if no inline
 * config is needed (the subtool works without config files).
 *
 * Each entry maps to a field that the ToolWorkspace renders as an
 * inline form. On RUN, the app writes each field's value to
 * WORK/<workFileName> transparently before calling the bridge.
 */
fun subToolConfig(subId: String): List<SubToolConfig> = when (subId) {
    // Module 12 — XOR Suite
    "xor_custom_key" -> listOf(
        SubToolConfig(
            field = "key_hex",
            label = "XOR Key (hex)",
            type = ConfigType.HEX,
            hint = "e.g. DEADBEEF00112233",
            workFileName = "xor_key.txt"
        )
    )
    "xor_batch" -> listOf(
        SubToolConfig(
            field = "key_hex",
            label = "XOR Key (hex)",
            type = ConfigType.HEX,
            hint = "Applied to all files in WORK/BATCH/",
            workFileName = "xor_key.txt"
        )
    )

    // Module 10 — SO Analyzer
    "so_multi_xor" -> listOf(
        SubToolConfig(
            field = "keys",
            label = "XOR Keys (one per line, hex)",
            type = ConfigType.MULTILINE,
            hint = "e.g. DEADBEEF\n00112233",
            workFileName = "xor_keys.txt"
        )
    )
    "so_patch_url" -> listOf(
        SubToolConfig(
            field = "patch_config",
            label = "Patch Config",
            type = ConfigType.MULTILINE,
            hint = "offset=0x1234 key=0xAB new_url=https://...",
            workFileName = "patch_config.txt"
        )
    )

    // Module 11 — Frida Tracer
    "frida_jni_hook", "frida_spawn" -> listOf(
        SubToolConfig(
            field = "target_pkg",
            label = "Target Package Name",
            type = ConfigType.TEXT,
            hint = "e.g. com.tencent.ig",
            workFileName = "frida_target.txt"
        )
    )

    // Module 13 — Decrypt Engine
    "dec_aes_cbc", "dec_aes_ecb" -> listOf(
        SubToolConfig(
            field = "aes_config",
            label = "AES Config",
            type = ConfigType.MULTILINE,
            hint = "key=<hex32>\niv=<hex16>",
            workFileName = "aes_config.txt"
        )
    )
    "dec_zuc" -> listOf(
        SubToolConfig(
            field = "zuc_config",
            label = "ZUC Config",
            type = ConfigType.MULTILINE,
            hint = "key=<hex32>\niv=<hex16>",
            workFileName = "zuc_config.txt"
        )
    )
    "dec_sm4" -> listOf(
        SubToolConfig(
            field = "sm4_config",
            label = "SM4 Config",
            type = ConfigType.MULTILINE,
            hint = "key=<hex32>\nmode=CBC|ECB\niv=<hex16>",
            workFileName = "sm4_config.txt"
        )
    )

    // Module 14 — PAK Deep
    "pak_deep_aes" -> listOf(
        SubToolConfig(
            field = "passphrase",
            label = "PAK Passphrase",
            type = ConfigType.TEXT,
            hint = "AES-SHA1 PAK passphrase",
            workFileName = "pak_pass.txt"
        )
    )
    "pak_deep_zuc" -> listOf(
        SubToolConfig(
            field = "zuc_config",
            label = "ZUC Config",
            type = ConfigType.MULTILINE,
            hint = "key=<hex32>\niv=<hex16>",
            workFileName = "zuc_config.txt"
        )
    )
    "pak_deep_sm4" -> listOf(
        SubToolConfig(
            field = "sm4_config",
            label = "SM4 Config",
            type = ConfigType.MULTILINE,
            hint = "key=<hex32>\nmode=CBC|ECB\niv=<hex16>",
            workFileName = "sm4_config.txt"
        )
    )

    // Module 16 — Lua Inject
    "lua_patch_byte" -> listOf(
        SubToolConfig(
            field = "patch_json",
            label = "Patch JSON",
            type = ConfigType.MULTILINE,
            hint = '{"offset": N, "opcode": N, "value": N}',
            workFileName = "lua_patch.json"
        )
    )
    "lua_inject_hook" -> listOf(
        SubToolConfig(
            field = "hook_code",
            label = "Hook Lua Source",
            type = ConfigType.MULTILINE,
            hint = "Lua function to inject",
            workFileName = "lua_hook.lua"
        )
    )

    // Module 3 — PAK Compact
    "pak_delete_entry" -> listOf(
        SubToolConfig(
            field = "targets",
            label = "Paths to Delete (one per line)",
            type = ConfigType.MULTILINE,
            hint = "Internal PAK paths to remove",
            workFileName = "delete_targets.txt"
        )
    )

    // Module 9 — Rebrand
    "rebrand_manual" -> listOf(
        SubToolConfig(
            field = "rebrand_config",
            label = "Rebrand Config",
            type = ConfigType.MULTILINE,
            hint = "brand=ALVSIA PRO\nchannel=t.me/ALVSIA_PRO\nwatermark=...",
            workFileName = "rebrand_config.txt"
        )
    )

    // Module 18 — Lua Protector
    "lua_protect_encrypt", "lua_protect_decrypt" -> listOf(
        SubToolConfig(
            field = "key_hex",
            label = "Lua Protector Key (64 hex chars)",
            type = ConfigType.HEX,
            hint = "32-byte AES-256-GCM key as 64 hex chars",
            workFileName = "lua_protect_key.txt"
        )
    )

    // All other subtools — no inline config needed
    else -> emptyList()
}

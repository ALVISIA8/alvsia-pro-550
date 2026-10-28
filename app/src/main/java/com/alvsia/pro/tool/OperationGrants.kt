package com.alvsia.pro.tool

import com.alvsia.pro.panel.PanelHolder

/** One least-privilege JWT grant per module operation, using the live Unaux contract. */
object OperationGrants {
    const val CORE_BUILD_ID = "ALVSIA-UNaux-20261028-RSA1"

    fun operationFor(moduleId: Int, subId: String): String? {
        val sid = subId.trim().lowercase()
        if (sid.startsWith("skin_obb")) return "skin_obb"
        if (sid.startsWith("game_patch")) return "game_patch"
        if (sid in setOf("audit_apk", "apk_audit")) return "apk_audit"
        if (sid.startsWith("priv_") || sid.startsWith("sm4_") ||
            sid in setOf("url_scan_so", "pubg_lua_convert")) return "alvsia_private_tool"
        return when (moduleId) {
            1, 2, 3, 14 -> "pak_tools"
            4 -> "obb_tools"
            5 -> "lua_tools"
            6 -> "file_scan"
            7 -> "workspace"
            8 -> "export_report"
            9 -> "rebrand"
            10 -> "so_analyzer"
            11 -> "frida_tracer"
            12 -> "xor_suite"
            13 -> "decrypt_engine"
            15 -> "string_recover"
            16 -> "lua_inject"
            17 -> "anti_re_audit"
            18 -> "lua_protector"
            19 -> "alvsia_private_tool"
            else -> null
        }
    }

    fun obtainAndInstall(operation: String): Pair<Boolean, String> {
        if (operation !in setOf(
            "pak_tools", "obb_tools", "skin_obb", "lua_tools", "file_scan",
            "workspace", "export_report", "rebrand", "so_analyzer", "frida_tracer",
            "xor_suite", "decrypt_engine", "string_recover", "lua_inject",
            "anti_re_audit", "lua_protector", "alvsia_private_tool", "game_patch", "apk_audit"
        )) return false to "operation is not allowlisted"
        val panel = PanelHolder.client ?: return false to "panel client unavailable"
        val result = panel.requestOperationGrant(operation, CORE_BUILD_ID)
        if (!result.ok || result.proofJson.isBlank()) return false to "panel grant rejected: ${result.message}"
        val installed = PythonBridgeRunner.installOperationProof(result.proofJson, operation)
        return if (installed) true to "Unaux RS256 JWT installed"
        else false to "engine rejected Unaux JWT grant"
    }
}

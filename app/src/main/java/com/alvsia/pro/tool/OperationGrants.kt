package com.alvsia.pro.tool

import com.alvsia.pro.panel.PanelHolder
import java.security.MessageDigest

/**
 * Requests least-privilege, short-lived server grants for core operations
 * that already enforce the RSA proof in alvsia_core.py.
 */
object OperationGrants {
    const val CORE_BUILD_ID = "ALVSIA-20260923-V46"
    val APK_SESSION_MEASUREMENT: String by lazy {
        MessageDigest.getInstance("SHA-256")
            .digest("ALVSIA-APK-SESSION".toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun operationsFor(moduleId: Int, subId: String): List<String> = when (moduleId) {
        1 -> listOf("pak.unpack")
        2 -> listOf("pak.repack")
        3 -> if (subId == "pak_delete_all") listOf("pak.delete_all")
             else listOf("pak.delete_entry", "pak.delete_all")
        14 -> listOf("pak.unpack")
        16 -> listOf("pak.repack")
        else -> emptyList()
    }

    fun obtainAndInstall(operations: List<String>): Pair<Boolean, String> {
        if (operations.isEmpty()) return true to "no grant required"
        val panel = PanelHolder.client ?: return false to "panel client unavailable"
        val result = panel.requestOperationGrant(
            operations = operations,
            buildId = CORE_BUILD_ID,
            manifestHash = APK_SESSION_MEASUREMENT,
            toolHash = APK_SESSION_MEASUREMENT
        )
        if (!result.ok || result.proofJson.isBlank()) return false to "panel grant rejected: ${result.message}"
        val installed = PythonBridgeRunner.installOperationProof(result.proofJson)
        return if (installed) true to "RSA proof installed: ${PythonBridgeRunner.proofStatus()}"
        else false to "engine rejected RSA proof"
    }
}

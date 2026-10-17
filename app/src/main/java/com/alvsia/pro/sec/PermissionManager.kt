package com.alvsia.pro.sec

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * ALVISIA PRO 5.5.0 — Per-tool PermissionManager.
 *
 * Design contract (per `perbaikan_source.txt` §5):
 *  • Zero-Confirmation by Default. The app never shows its OWN confirmation
 *    dialog. If the OS forces a runtime dialog, that's the only dialog.
 *  • Each tool declares only the permissions it actually needs. We do not
 *    ask for all permissions at startup.
 *  • Before a tool runs, `ensureForTool(ctx, toolId)` checks the relevant
 *    permissions. Already-granted permissions are not re-requested.
 *  • After a tool run returns, the OS callback `onPermissionResult` resumes
 *    the operation if context is still valid.
 *  • Special app access that cannot be granted via dialog (MANAGE_EXTERNAL_STORAGE,
 *    Draw over other apps, Usage stats) is opened via the official Android
 *    Settings intent. When the user returns, we detect and continue.
 *  • Cache invalidates on onResume so a permission revoked while the app
 *    was backgrounded is detected.
 *  • Optional acceleration via ADB pm grant / root is detected but never
 *    silently elevates privileges — only uses what the system already
 *    granted.
 *  • Never lies about success. BLOCKED status carries a concrete reason.
 */

// ── Per-tool permission matrix ─────────────────────────────────────────────
//
// Each tool maps to a list of (permission, flow) pairs.
// Flow values: "install_time", "runtime_auto", "settings_intent", "fallback"
//
// Install-time (normal) permissions are auto-granted at install and never
// produce a dialog. Runtime permissions are requested just-in-time and at
// most one system dialog appears (the only confirmation the user ever sees).
// Settings-intent permissions cannot be granted via dialog and require the
// user to flip a Settings toggle; we open the official Settings page and
// detect via onResume.
//
// Tools that do not need any permission return an empty list.

data class ToolPermission(
    val permission: String,
    val flow: String,
    val rationale: String
)

object ToolPermissionMatrix {
    /** Returns the permission list required for [toolId] in priority order. */
    fun forTool(toolId: Int): List<ToolPermission> = when (toolId) {
        // 1 PAK Unpack — file read + write
        1 -> listOf(
            ToolPermission("android.permission.READ_EXTERNAL_STORAGE", "runtime_auto", "Read selected .pak"),
            ToolPermission("android.permission.WRITE_EXTERNAL_STORAGE", "runtime_auto", "Write OUT/PAK"),
            ToolPermission("android.permission.MANAGE_EXTERNAL_STORAGE", "settings_intent", "Bulk PAK access on Android 11+"),
            ToolPermission("android.permission.READ_MEDIA_IMAGES", "runtime_auto", "Scoped media on Android 13+"),
        )
        // 2 PAK Rebuild — same as 1
        2 -> forTool(1)
        // 3 PAK Compact — same as 1
        3 -> forTool(1)
        // 4 OBB Tools
        4 -> forTool(1)
        // 5 LUA Tools
        5 -> forTool(1)
        // 6 File Scan
        6 -> forTool(1)
        // 7 Workspace clear — no extra perms (uses app-private path or shared Download)
        7 -> listOf(
            ToolPermission("android.permission.WRITE_EXTERNAL_STORAGE", "runtime_auto", "Wipe OUT/WORK tree"),
            ToolPermission("android.permission.MANAGE_EXTERNAL_STORAGE", "settings_intent", "Wipe shared Download tree on Android 11+"),
        )
        // 8 Export Report
        8 -> forTool(1)
        // 9 Rebrand
        9 -> forTool(1)
        // 10 SO Analyzer
        10 -> forTool(1)
        // 11 Frida Tracer — needs query packages + (optional) root via ADB
        11 -> listOf(
            ToolPermission("android.permission.QUERY_ALL_PACKAGES", "install_time", "List installed packages for hook target"),
            ToolPermission("android.permission.READ_EXTERNAL_STORAGE", "runtime_auto", "Read .so/.apk inputs"),
            ToolPermission("android.permission.WRITE_EXTERNAL_STORAGE", "runtime_auto", "Write OUT/FRIDA"),
            ToolPermission("android.permission.MANAGE_EXTERNAL_STORAGE", "settings_intent", "Bulk access on Android 11+"),
        )
        // 12 XOR Suite
        12 -> forTool(1)
        // 13 Decrypt Engine
        13 -> forTool(1)
        // 14 PAK Deep
        14 -> forTool(1)
        // 15 String Recover
        15 -> forTool(1)
        // 16 Lua Inject
        16 -> forTool(1)
        // 17 Anti-RE Audit
        17 -> listOf(
            ToolPermission("android.permission.QUERY_ALL_PACKAGES", "install_time", "List installed packages for APK audit"),
            ToolPermission("android.permission.READ_EXTERNAL_STORAGE", "runtime_auto", "Read .apk/.so/.lua"),
            ToolPermission("android.permission.WRITE_EXTERNAL_STORAGE", "runtime_auto", "Write OUT/AUDIT"),
            ToolPermission("android.permission.MANAGE_EXTERNAL_STORAGE", "settings_intent", "Bulk access on Android 11+"),
            ToolPermission("android.permission.REQUEST_INSTALL_PACKAGES", "settings_intent", "Optional APK install audit"),
        )
        // 18 Lua Protector
        18 -> forTool(1)
        else -> emptyList()
    }
}

enum class PermissionStatus { GRANTED, BLOCKED, NEEDS_DIALOG, NEEDS_SETTINGS }
data class PermissionCheckResult(
    val permission: String,
    val status: PermissionStatus,
    val reason: String
)

/**
 * Singleton permission manager. Stateful across the activity lifecycle:
 * holds the pending tool re-run so the OS callback can resume it.
 */
object PermissionManager {

    private const val REQ_CODE_BASE = 0xA00   // base request code
    private const val REQ_CODE_RANGE = 64      // reserved range for runtime perms

    @Volatile private var cache: Map<String, Boolean>? = null
    @Volatile private var cacheInvalidated: Boolean = false

    /** Pending tool resume (toolId, runnable). Used by onPermissionResult. */
    @Volatile private var pendingResume: Pair<Int, (() -> Unit)?>? = null

    /** Invalidate cache on resume. Called from Activity.onResume. */
    fun invalidate() { cacheInvalidated = true }

    /** Check whether all permissions for a tool are granted. */
    fun check(ctx: Context, toolId: Int): List<PermissionCheckResult> {
        val out = mutableListOf<PermissionCheckResult>()
        for (tp in ToolPermissionMatrix.forTool(toolId)) {
            val granted = isGranted(ctx, tp.permission)
            val status = when {
                granted -> PermissionStatus.GRANTED
                tp.flow == "install_time" -> PermissionStatus.BLOCKED
                tp.flow == "runtime_auto" -> PermissionStatus.NEEDS_DIALOG
                tp.flow == "settings_intent" -> PermissionStatus.NEEDS_SETTINGS
                else -> PermissionStatus.BLOCKED
            }
            out.add(PermissionCheckResult(tp.permission, status, tp.rationale))
        }
        return out
    }

    fun isGranted(ctx: Context, permission: String): Boolean {
        // Cache invalidation hook
        if (cacheInvalidated) {
            cache = null
            cacheInvalidated = false
        }
        // Special-case permissions that are not checkable via checkSelfPermission
        when (permission) {
            "android.permission.MANAGE_EXTERNAL_STORAGE" -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return true
                return Environment.isExternalStorageManager()
            }
            "android.permission.WRITE_SETTINGS" -> {
                return Settings.System.canWrite(ctx)
            }
            "android.permission.PACKAGE_USAGE_STATS" -> {
                val appOps = ctx.getSystemService(Context.APP_OPS_SERVICE) as? android.app.AppOpsManager
                return appOps?.let {
                    val mode = it.unsafeCheckOpNoThrow(
                        android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
                        android.os.Process.myUid(),
                        ctx.packageName
                    )
                    mode == android.app.AppOpsManager.MODE_ALLOWED
                } ?: false
            }
            "android.permission.SYSTEM_ALERT_WINDOW" -> {
                return Settings.canDrawOverlays(ctx)
            }
            "android.permission.REQUEST_INSTALL_PACKAGES" -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true
                return ctx.packageManager.canRequestPackageInstalls()
            }
        }
        // Fast path via cache
        val c = cache
        if (c != null && c[permission] == true) return true
        val granted = ContextCompat.checkSelfPermission(ctx, permission) ==
            PackageManager.PERMISSION_GRANTED
        if (c != null) {
            (c as MutableMap<String, Boolean>)[permission] = granted
        }
        return granted
    }

    /**
     * Ensure all permissions for [toolId] are satisfied. If everything is
     * already granted, [onReady] runs immediately. Otherwise we fire the
     * runtime dialog (no app-level dialog) and/or open Settings intent
     * for special-access permissions. The runnable is stashed so
     * onPermissionResult / onResume can resume it.
     */
    fun ensureForTool(activity: Activity, toolId: Int, onReady: () -> Unit) {
        val checks = check(activity, toolId)

        // 1) If all granted, fire immediately.
        if (checks.all { it.status == PermissionStatus.GRANTED }) {
            onReady()
            return
        }

        // 2) Stash the resume callback. The OS callback will resume it.
        pendingResume = toolId to onReady

        // 3) Collect runtime perms to request (NEEDS_DIALOG)
        val runtimePerms = checks
            .filter { it.status == PermissionStatus.NEEDS_DIALOG }
            .map { it.permission }
            .toTypedArray()

        if (runtimePerms.isNotEmpty()) {
            try {
                ActivityCompat.requestPermissions(
                    activity,
                    runtimePerms,
                    REQ_CODE_BASE + (toolId % REQ_CODE_RANGE)
                )
                // The OS dialog is the ONLY confirmation the user sees.
                // onPermissionResult will resume the operation.
                return
            } catch (_: Exception) {
                // fall through to settings-intent if requestPermissions failed
            }
        }

        // 4) Open Settings intent for special-access perms (NEEDS_SETTINGS)
        val settingsNeeded = checks.firstOrNull { it.status == PermissionStatus.NEEDS_SETTINGS }
        if (settingsNeeded != null) {
            openSettingsIntent(activity, settingsNeeded.permission)
            return
        }

        // 5) Pure block (install-time permission missing) — caller must show
        //    a truthful BLOCKED message in UI logs.
        val blocked = checks.firstOrNull { it.status == PermissionStatus.BLOCKED }
        if (blocked != null) {
            // Do not run the tool. Caller (ToolEngine) will get a BLOCKED
            // diagnostic by re-checking the matrix in run().
            // No-op here; the runnable stays pending and is cleared on resume.
        }
    }

    /**
     * Resume callback after OS dialog or Settings return.
     * If all permissions for the pending tool are now granted, fire [onReady].
     * Otherwise drop the pending runnable so the user has to retry — we do
     * not silently bypass.
     */
    fun onPermissionResult(activity: Activity, requestCode: Int, grantResults: IntArray) {
        val pending = pendingResume ?: return
        val toolId = pending.first
        if ((requestCode - REQ_CODE_BASE) % REQ_CODE_RANGE != toolId % REQ_CODE_RANGE) {
            // not our request
            return
        }
        // Force invalidate and re-check
        invalidate()
        val checks = check(activity, toolId)
        if (checks.all { it.status == PermissionStatus.GRANTED }) {
            val cb = pending.second
            pendingResume = null
            cb?.invoke()
        } else {
            // Some denied — caller will display BLOCKED on next tool attempt.
            // Clear pending so user retry re-evaluates fresh.
            pendingResume = null
        }
    }

    /**
     * Called from Activity.onResume so we can resume an operation that was
     * waiting for a Settings-intent (e.g. MANAGE_EXTERNAL_STORAGE).
     */
    fun onResume(activity: Activity) {
        invalidate()
        val pending = pendingResume ?: return
        val toolId = pending.first
        val checks = check(activity, toolId)
        if (checks.all { it.status == PermissionStatus.GRANTED }) {
            val cb = pending.second
            pendingResume = null
            cb?.invoke()
        }
        // else: keep pending (still missing permissions)
    }

    /**
     * Optional ADB/root acceleration hook. We never elevate privileges
     * silently — we just observe whether the system already granted the
     * permission via pm grant. Useful for test/CI builds.
     */
    fun maybeAdbGranted(ctx: Context, permission: String): Boolean {
        // Just delegate to isGranted — we don't try to escalate.
        return isGranted(ctx, permission)
    }

    /** Returns true if any required permission for [toolId] is BLOCKED. */
    fun isBlocked(ctx: Context, toolId: Int): Boolean =
        check(ctx, toolId).any { it.status == PermissionStatus.BLOCKED }

    /** Returns a human-readable status summary for [toolId]. */
    fun statusSummary(ctx: Context, toolId: Int): String {
        val checks = check(ctx, toolId)
        if (checks.isEmpty()) return "no permissions required"
        if (checks.all { it.status == PermissionStatus.GRANTED }) return "all permissions granted"
        return checks.filter { it.status != PermissionStatus.GRANTED }
            .joinToString("; ") { "${it.permission}=${it.status}" }
    }

    private fun openSettingsIntent(activity: Activity, permission: String) {
        try {
            val intent = when (permission) {
                "android.permission.MANAGE_EXTERNAL_STORAGE" ->
                    Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                    }
                "android.permission.SYSTEM_ALERT_WINDOW" ->
                    Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                    }
                "android.permission.PACKAGE_USAGE_STATS" ->
                    Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                "android.permission.REQUEST_INSTALL_PACKAGES" ->
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                    }
                "android.permission.WRITE_SETTINGS" ->
                    Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                    }
                else -> null
            } ?: return
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
        } catch (_: Exception) {
            // Fallback: generic Settings page
            try {
                activity.startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                )
            } catch (_: Exception) { /* nothing we can do */ }
        }
    }
}

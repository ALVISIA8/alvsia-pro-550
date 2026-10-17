package com.alvsia.pro.sec

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * Handles all runtime permissions for ALVSIA PRO.
 * - READ/WRITE_EXTERNAL_STORAGE  (Android <= 12)
 * - MANAGE_EXTERNAL_STORAGE      (Android 11+, files:///sdcard/ access)
 * - RECORD_AUDIO                 (for audio tool modules)
 * - READ_PHONE_STATE              (HWID derivation)
 *
 * Call requestAll(activity) once from the first screen the user sees after login.
 * No confirmation dialogs from the app — all permissions fire simultaneously.
 */
object PermissionHelper {

    private val RUNTIME_PERMS = mutableListOf(
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.READ_PHONE_STATE,
    ).apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.READ_MEDIA_IMAGES)
            add(Manifest.permission.READ_MEDIA_AUDIO)
            add(Manifest.permission.READ_MEDIA_VIDEO)
        }
    }.toTypedArray()

    const val REQ_CODE = 0xA1   // 161 — safe range

    /** Fire all runtime permissions in one system dialog pass. */
    fun requestAll(activity: Activity) {
        val missing = RUNTIME_PERMS.filter {
            ContextCompat.checkSelfPermission(activity, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(activity, missing.toTypedArray(), REQ_CODE)
        }
        // MANAGE_EXTERNAL_STORAGE requires its own Settings intent on Android 11+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                        data = Uri.fromParts("package", activity.packageName, null)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    activity.startActivity(intent)
                } catch (_: Exception) {
                    // Fallback: open generic all-files settings
                    try {
                        activity.startActivity(
                            Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    } catch (_: Exception) { }
                }
            }
        }
    }

    /** True when all storage permissions needed for tool execution are granted. */
    fun storageOk(activity: Activity): Boolean {
        val legacyOk = ContextCompat.checkSelfPermission(
            activity, Manifest.permission.WRITE_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
        val manageOk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else true
        return legacyOk || manageOk
    }
}

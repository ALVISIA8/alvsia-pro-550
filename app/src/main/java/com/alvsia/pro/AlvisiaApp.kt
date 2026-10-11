package com.alvsia.pro

import android.app.Application
import android.util.Log
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Start Chaquopy before optional security telemetry. A failure in a
        // telemetry component must never prevent Python from being initialized.
        try {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(this))
            }
            Log.i(TAG, "Chaquopy startup completed; started=${Python.isStarted()}")
        } catch (e: Exception) {
            // Chaquopy cannot be restarted after a failed startup. Preserve the
            // original exception in logcat so the root cause can be diagnosed.
            Log.e(TAG, "Chaquopy startup failed; runtime cannot be retried in this process", e)
        } catch (e: LinkageError) {
            Log.e(TAG, "Chaquopy/native linkage failed during startup", e)
        }

        try {
            Guard.checkAndReport(this)
        } catch (e: Exception) {
            Log.e(TAG, "Guard startup check failed", e)
        }
        try {
            EnvProbe.report(this)
        } catch (e: Exception) {
            Log.e(TAG, "Environment probe failed", e)
        }
        try {
            RaspEngine.start(this)
        } catch (e: Exception) {
            Log.e(TAG, "RASP engine startup failed", e)
        }
    }

    private companion object {
        const val TAG = "ALVISIA_STARTUP"
    }
}

package com.alvsia.pro

import android.app.Application
import android.os.Process
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Do not hold Application.onCreate() on expensive integrity/RASP/Python
        // initialization. A blocked Application startup prevents MainActivity
        // and its splash animation from being drawn at all.
        Thread({
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
            try {
                Guard.checkAndReport(this)
                EnvProbe.report(this)
                RaspEngine.start(this)
            } catch (_: Throwable) {
                // Initialization is best-effort here; the live session gate
                // still enforces authorization before tool dispatch.
            }

            // Start Python off the UI thread so Chaquopy extraction/import work
            // cannot freeze the first frame. PythonBridgeRunner records a
            // diagnostic if startup fails; tool dispatch has a native fallback.
            try {
                PythonBridgeRunner.startPlatform(this)
            } catch (_: Throwable) {
                // Keep the launcher responsive; diagnostics remain available.
            }
        }, "alvisia-runtime-init").start()
    }
}

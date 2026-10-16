package com.alvsia.pro

import android.app.Application
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            Guard.checkAndReport(this)
            EnvProbe.report(this)
            RaspEngine.start(this)
        } catch (_: Exception) {
        }
        // Start Python via reflection so the class is optional at link time
        try {
            PythonBridgeRunner.startPlatform(this)
        } catch (_: Exception) {
        }
    }
}

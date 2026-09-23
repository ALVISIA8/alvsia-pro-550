package com.alvsia.pro

import android.app.Application
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            Guard.checkAndReport(this)
            EnvProbe.report(this)
            RaspEngine.start(this)
        } catch (_: Exception) {
        }
        try {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(this))
            }
        } catch (_: Exception) {
        }
    }
}

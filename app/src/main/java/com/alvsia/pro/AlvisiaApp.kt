package com.alvsia.pro

import android.app.Application
import android.util.Log
import app.talsec.android.Talsec
import app.talsec.android.TalsecCallback
import app.talsec.android.TalsecConfig
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Initialize vendor RASP independently so a configuration/API issue cannot
        // prevent the existing guard or Chaquopy bridge from starting.
        try {
            val config = TalsecConfig(
                expectedPackageName = "com.alvsia.pro",
                expectedSigningHashes = listOf("mbM4FciKF6u8/iK+FSUDY/bfx5wR/8mA5xtit0sfKVw="),
                callback = object : TalsecCallback {
                    override fun onRootDetected() = reportThreat("root")
                    override fun onDebuggerDetected() = reportThreat("debugger")
                    override fun onEmulatorDetected() = reportThreat("emulator")
                    override fun onTamperDetected() = reportThreat("tamper")
                    override fun onUntrustedInstallationDetected() = reportThreat("untrusted-install")
                    override fun onHookDetected() = reportThreat("hook")
                    override fun onDeviceBindingDetected() = reportThreat("device-binding")
                    override fun onObfuscationIssuesDetected() = reportThreat("obfuscation")
                    override fun onScreenshotDetected() = reportThreat("screenshot")
                    override fun onScreenRecordingDetected() = reportThreat("screen-recording")
                    override fun onMultiInstanceDetected() = reportThreat("multi-instance")
                    override fun onLocationSpoofingDetected() = reportThreat("location-spoofing")
                    override fun onTimeSpoofingDetected() = reportThreat("time-spoofing")
                    override fun onUnsecureWifiDetected() = reportThreat("unsecure-wifi")
                },
                isProd = !BuildConfig.DEBUG,
                killOnBypass = false
            )
            Talsec.start(this, config)
        } catch (e: Exception) {
            Log.w("ALVISIA-RASP", "freeRASP initialization unavailable; native guard remains active", e)
        }

        try {
            Guard.checkAndReport(this)
            EnvProbe.report(this)
            RaspEngine.start(this)
        } catch (e: Exception) {
            Log.w("ALVISIA-RASP", "Existing guard initialization reported an error", e)
        }
        try {
            PythonBridgeRunner.startPlatform(this)
        } catch (e: Exception) {
            Log.e("ALVISIA-RASP", "Python bridge initialization failed", e)
        }
    }

    private fun reportThreat(type: String) {
        // Minimal local event only: no HWID, screenshot, license key, or OTP is sent.
        Log.w("ALVISIA-RASP", "Threat signal: $type")
    }
}

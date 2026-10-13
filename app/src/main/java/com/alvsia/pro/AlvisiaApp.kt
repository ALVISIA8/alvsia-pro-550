package com.alvsia.pro

import android.app.Application
import android.util.Log
import app.talsec.android.Talsec
import app.talsec.android.TalsecConfig
import app.talsec.android.ThreatDetected
import app.talsec.android.ThreatListener
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Talsec is defense-in-depth. Do not terminate users on a single heuristic;
        // existing authorization/session checks remain the source of access decisions.
        try {
            val listener = ThreatListener(object : ThreatDetected() {
                override fun onPrivilegedAccess() = reportThreat("root-or-privileged-access")
                override fun onDebug() = reportThreat("debugger")
                override fun onSimulator() = reportThreat("emulator")
                override fun onAppIntegrity() = reportThreat("app-integrity")
                override fun onUnofficialStore() = reportThreat("untrusted-install")
                override fun onHooks() = reportThreat("hook")
                override fun onDeviceBinding() = reportThreat("device-binding")
                override fun onObfuscationIssues() = reportThreat("obfuscation")
                override fun onScreenshot() = reportThreat("screenshot")
                override fun onScreenRecording() = reportThreat("screen-recording")
                override fun onMultiInstance() = reportThreat("multi-instance")
                override fun onLocationSpoofing() = reportThreat("location-spoofing")
                override fun onTimeSpoofing() = reportThreat("time-spoofing")
                override fun onUnsecureWifi() = reportThreat("unsecure-wifi")
                override fun onAutomation() = reportThreat("automation")
                override fun onBootloader() = reportThreat("bootloader")
            })
            listener.registerListener(this)
            val config = TalsecConfig(
                expectedPackageName = "com.alvsia.pro",
                expectedSigningCertificateHashBase64 = arrayOf(
                    "mbM4FciKF6u8/iK+FSUDY/bfx5wR/8mA5xtit0sfKVw="
                ),
                watcherMail = null,
                supportedAlternativeStores = emptyArray(),
                isProd = !BuildConfig.DEBUG,
                killOnBypass = false
            )
            Talsec.start(this, config)
        } catch (e: Exception) {
            Log.w("ALVISIA-RASP", "freeRASP initialization unavailable; existing guards remain active", e)
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

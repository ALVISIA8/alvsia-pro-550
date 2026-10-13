package com.alvsia.pro

import android.app.Application
import android.util.Log
import app.talsec.rasp.security.api.SuspiciousAppInfo
import app.talsec.rasp.security.api.Talsec
import app.talsec.rasp.security.api.TalsecConfig
import app.talsec.rasp.security.api.ThreatListener
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application() {
    private val threatDetected = object : ThreatListener.ThreatDetected() {
        override fun onPrivilegedAccess() = reportThreat("root")
        override fun onDebug() = reportThreat("debugger")
        override fun onSimulator() = reportThreat("emulator")
        override fun onAppIntegrity() = reportThreat("tamper")
        override fun onUnofficialStore() = reportThreat("untrusted-install")
        override fun onHooks() = reportThreat("hook")
        override fun onDeviceBinding() = reportThreat("device-binding")
        override fun onObfuscationIssues() = reportThreat("obfuscation")
        override fun onAutomation() = reportThreat("automation")
        override fun onScreenshot() = reportThreat("screenshot")
        override fun onScreenRecording() = reportThreat("screen-recording")
        override fun onMultiInstance() = reportThreat("multi-instance")
        override fun onUnsecureWifi() = reportThreat("unsecure-wifi")
        override fun onTimeSpoofing() = reportThreat("time-spoofing")
        override fun onLocationSpoofing() = reportThreat("location-spoofing")
        override fun onBootloader() = reportThreat("bootloader")

        override fun onMalware(suspiciousApps: List<SuspiciousAppInfo>) {
            reportThreat("malware-count-" + suspiciousApps.size)
        }
    }

    override fun onCreate() {
        super.onCreate()

        // RASP is defense-in-depth; server/session/operation-grant checks remain authoritative.
        try {
            val config = TalsecConfig.Builder(
                "com.alvsia.pro",
                arrayOf("mbM4FciKF6u8/iK+FSUDY/bfx5wR/8mA5xtit0sfKVw=")
            )
                .supportedAlternativeStores(emptyArray())
                .prod(!BuildConfig.DEBUG)
                .killOnBypass(false)
                .build()
            ThreatListener(threatDetected).registerListener(this)
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
        // Local minimal event only; no HWID, screenshot, license key, or OTP is sent.
        Log.w("ALVISIA-RASP", "Threat signal: " + type)
    }
}

package com.alvsia.pro

import android.app.Application
import android.util.Log
import com.aheaditec.talsec_security.security.api.SuspiciousAppInfo
import com.aheaditec.talsec_security.security.api.Talsec
import com.aheaditec.talsec_security.security.api.TalsecConfig
import com.aheaditec.talsec_security.security.api.ThreatListener
import com.alvsia.pro.sec.EnvProbe
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.tool.PythonBridgeRunner

class AlvisiaApp : Application(), ThreatListener.ThreatDetected {
    override fun onCreate() {
        super.onCreate()

        // Runtime detection is defense-in-depth. A single heuristic does not grant
        // or revoke licenses; existing server/session/operation-grant checks remain authoritative.
        try {
            val config = TalsecConfig.Builder(
                "com.alvsia.pro",
                arrayOf("mbM4FciKF6u8/iK+FSUDY/bfx5wR/8mA5xtit0sfKVw=")
            )
                .supportedAlternativeStores(emptyArray())
                .prod(!BuildConfig.DEBUG)
                .killOnBypass(false)
                .build()
            ThreatListener(this).registerListener(this)
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

    override fun onRootDetected() = reportThreat("root")
    override fun onDebuggerDetected() = reportThreat("debugger")
    override fun onEmulatorDetected() = reportThreat("emulator")
    override fun onTamperDetected() = reportThreat("tamper")
    override fun onUntrustedInstallationSourceDetected() = reportThreat("untrusted-install")
    override fun onHookDetected() = reportThreat("hook")
    override fun onDeviceBindingDetected() = reportThreat("device-binding")
    override fun onObfuscationIssuesDetected() = reportThreat("obfuscation")
    override fun onAutomationDetected() = reportThreat("automation")
    override fun onScreenshotDetected() = reportThreat("screenshot")
    override fun onScreenRecordingDetected() = reportThreat("screen-recording")
    override fun onMultiInstanceDetected() = reportThreat("multi-instance")
    override fun onUnsecureWifiDetected() = reportThreat("unsecure-wifi")
    override fun onTimeSpoofingDetected() = reportThreat("time-spoofing")
    override fun onLocationSpoofingDetected() = reportThreat("location-spoofing")

    override fun onMalwareDetected(suspiciousApps: MutableList<SuspiciousAppInfo>?) {
        reportThreat("malware-count-" + (suspiciousApps?.size ?: 0))
    }

    private fun reportThreat(type: String) {
        // Local minimal event only; no HWID, screenshot, license key, or OTP is sent.
        Log.w("ALVISIA-RASP", "Threat signal: " + type)
    }
}

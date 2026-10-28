#!/usr/bin/env python3
"""Regression checks that release security controls remain wired into runtime."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

def read(path):
    return (ROOT / path).read_text(encoding="utf-8")

class SecurityWiringTests(unittest.TestCase):
    def test_manifest_security_baseline(self):
        m = read("app/src/main/AndroidManifest.xml")
        self.assertIn('android:allowBackup="false"', m)
        self.assertIn('android:networkSecurityConfig="@xml/network_security_config"', m)
        self.assertIn('android:name=".AlvisiaApp"', m)

    def test_unaux_tls_pin_is_strictly_configured(self):
        x = read("app/src/main/res/xml/network_security_config.xml")
        vault = read("app/src/main/java/com/alvsia/pro/panel/Vault.kt")
        panel = read("app/src/main/java/com/alvsia/pro/panel/PanelClient.kt")
        py = read("app/src/main/python/pinned_http.py")
        self.assertIn('cleartextTrafficPermitted="false"', x)
        self.assertNotIn("alvsiapanel.unaux.com", x,
                         "panel hostname must not be duplicated in plaintext XML")
        self.assertIn("private fun decodedOrigin()", vault)
        self.assertIn('.add(panelHost(), "sha256/', vault)
        pins = re.findall(r'sha256/([A-Za-z0-9+/]{43}=)', vault)
        self.assertTrue(pins, "missing runtime OkHttp SPKI pin")
        import base64
        for pin in pins:
            self.assertEqual(len(base64.b64decode(pin, validate=True)), 32)
        self.assertIn(".certificatePinner(Vault.certPinner())", panel)
        self.assertIn(".followRedirects(false)", panel)
        self.assertIn(".followSslRedirects(false)", panel)
        self.assertIn('kwargs["allow_redirects"] = False', py)
        encoded = (0x01, 0x1c, 0x1f, 0x1a, 0x1e, 0x56, 0x40, 0x41,
                   0x00, 0x0c, 0x15, 0x11, 0x0c, 0x05, 0x17, 0x07,
                   0x17, 0x1d, 0x17, 0x54, 0x08, 0x12, 0x1e, 0x0b,
                   0x09, 0x5e, 0x10, 0x1d, 0x18)
        origin = bytes(v ^ 0x5A ^ (i & 0x3F) ^ 0x33
                       for i, v in enumerate(encoded)).decode("utf-8")
        self.assertEqual(origin, "https://alvsiapanel.unaux.com")
        self.assertIn("_panel_host()", py)

    def test_runtime_security_bootstrap_is_wired(self):
        app = read("app/src/main/java/com/alvsia/pro/AlvisiaApp.kt")
        self.assertIn("RaspEngine.start(this)", app)
        self.assertIn("Guard.checkAndReport(this)", app)
        self.assertIn("EnvProbe.report(this)", app)

    def test_every_protected_dispatch_rechecks_integrity_and_session(self):
        gate = read("app/src/main/java/com/alvsia/pro/sec/SessionGate.kt")
        self.assertIn("fun allowTools(ctx: Context)", gate)
        self.assertIn("runtimeHostile(ctx)", gate)
        self.assertIn("DualVmGuard.inspect(ctx)", gate)
        self.assertIn("IntegrityBomb.isCompromised(ctx)", gate)
        self.assertIn("if (!sessionOk)", gate)
        self.assertIn("SESSION_TTL", gate)

    def test_rasp_layers_include_debug_hook_memory_and_integrity(self):
        rasp = read("app/src/main/java/com/alvsia/pro/sec/RaspEngine.kt")
        for marker in ("Debug.isDebuggerConnected()", "FridaProbe.signals()",
                       "MemoryGuard.detectPtrace()", "IntegrityBomb.evaluate(ctx)",
                       "DualVmGuard.inspect(ctx)", "NativeGuard.antiDump()"):
            self.assertIn(marker, rasp)

    def test_sealed_payloads_fail_closed_and_release_signing_is_verified(self):
        guard = read("app/src/main/java/com/alvsia/pro/sec/NativeGuard.kt")
        seal = read("tools/seal_python.py")
        yaml = read("codemagic.yaml")
        self.assertIn("decryptSealedPayload", guard)
        self.assertIn("AES/GCM/NoPadding", guard)
        self.assertIn("ALVSEAL2", seal)
        self.assertIn("CM_KEY_ALIAS", yaml)
        self.assertIn("apksigner", yaml)
        self.assertIn("CERT_SHA256", yaml)

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Non-invasive release checks for ALVSIA PRO. Does not modify source or permissions."""
from pathlib import Path
import base64
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)

catalog = ROOT / "app/src/main/java/com/alvsia/pro/tool/ToolCatalog.kt"
manifest = ROOT / "app/src/main/AndroidManifest.xml"
network = ROOT / "app/src/main/res/xml/network_security_config.xml"
profile = ROOT / "app/src/main/java/com/alvsia/pro/ui/profile/ProfileScreen.kt"

for file in (catalog, manifest, network, profile):
    if not file.is_file():
        fail(f"required file missing: {file.relative_to(ROOT)}")

catalog_text = catalog.read_text(encoding="utf-8")
ids = [int(x) for x in re.findall(r"ToolItem\(\s*(\d+)\s*,", catalog_text)]
if sorted(set(ids)) != list(range(1, 20)):
    fail(f"catalog must define IDs 1..19 exactly; found {sorted(set(ids))}")
print("PASS: catalog defines all 19 module IDs")

profile_text = profile.read_text(encoding="utf-8")
if "ModuleChip(\"⚙\",\"ALVSIA PRIVATE TOOL\")" not in profile_text or "19" not in profile_text:
    fail("profile must retain the private module and 19-module label")
print("PASS: profile retains the private module")

manifest_text = manifest.read_text(encoding="utf-8")
for required in (
    'android:allowBackup="false"',
    'android.permission.INTERNET',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.READ_PHONE_STATE',
    'android.permission.REQUEST_INSTALL_PACKAGES',
):
    if required not in manifest_text:
        fail(f"manifest baseline missing: {required}")
print("PASS: required existing permissions and backup setting are present")

network_text = network.read_text(encoding="utf-8")
vault_path = ROOT / "app/src/main/java/com/alvsia/pro/panel/Vault.kt"
vault_text = vault_path.read_text(encoding="utf-8") if vault_path.is_file() else ""
panel_client_path = ROOT / "app/src/main/java/com/alvsia/pro/panel/PanelClient.kt"
panel_client_text = panel_client_path.read_text(encoding="utf-8") if panel_client_path.is_file() else ""
if 'cleartextTrafficPermitted="false"' not in network_text:
    fail("cleartext traffic must remain disabled")
if "alvsiapanel.unaux.com" in network_text:
    fail("panel hostname must not be duplicated in plaintext network XML")
pin_match = re.search(r'sha256/([A-Za-z0-9+/]{43}=)', vault_text)
if not pin_match:
    fail("no SHA-256 SPKI pin configured in Vault")
try:
    decoded_pin = base64.b64decode(pin_match.group(1), validate=True)
except Exception:
    fail("Vault SPKI pin is not valid base64")
if len(decoded_pin) != 32:
    fail(f"SPKI SHA-256 pin must decode to 32 bytes, got {len(decoded_pin)}")
if ("private fun decodedOrigin()" not in vault_text
        or "intArrayOf(" not in vault_text
        or "encoded[i] xor 0x5A xor (i and 0x3F) xor 0x33" not in vault_text
        or '.add(panelHost(), "sha256/' not in vault_text):
    fail("runtime endpoint decoder or host-bound pin configuration is missing")
if ".certificatePinner(Vault.certPinner())" not in panel_client_text:
    fail("active PanelClient does not attach the Vault certificate pinner")
print("PASS: HTTPS-only config, runtime-obfuscated endpoint, and SHA-256 SPKI pin format")

print("PASS: release safety audit completed; runtime and device tests are still required")

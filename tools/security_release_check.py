#!/usr/bin/env python3
"""ALVISIA PRO R5.2 release gate: protected Python must be sealed at rest."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "app/src/main/python"
JAVA = ROOT / "app/src/main/java"
forbidden = ["ALVSIA_" + "SOFT_AUTH", "ALVSIA_" + "APK_SESSION"]
private_markers = ["BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"]
fail=[]
warn=[]
for base in (PY,JAVA):
    if not base.exists(): continue
    for p in base.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {".py",".kt",".java",".cpp",".h"}: continue
        try: text=p.read_text(errors="ignore")
        except: continue
        for marker in forbidden+private_markers:
            if marker in text: fail.append(f"{p.relative_to(ROOT)}: forbidden marker {marker}")
protected = [
    "alvsia_core.py","alvsia_ultimate.py","alvsia_features.py",
    "lua_output_validator.py","lua_string_recover.py",
    "lua_engine/engine.py","lua_engine/decompiler53.py","lua_engine/bgmi.py",
    "lua_engine/luajit_decompiler.py","lua_engine/container.py",
    "lua_engine/detector.py","lua_engine/multi_format.py","lua_engine/vm_deobfuscator.py"
]
for rel in protected:
    if (PY/rel).exists(): fail.append(f"plaintext protected module still present: {rel}")
sealed=list((PY/"sealed").glob("*.alv")) if (PY/"sealed").exists() else []
if len(sealed) < len(protected): fail.append(f"sealed payload count {len(sealed)} < {len(protected)}")
for req in [PY/"sealed_loader.py", PY/"alvsia_bridge.py",
            ROOT/"app/src/main/java/com/alvsia/pro/tool/ToolEngine.kt",
            ROOT/"app/src/main/java/com/alvsia/pro/sec/NativeGuard.kt"]:
    if not req.exists(): fail.append(f"missing required security file: {req.relative_to(ROOT)}")
if "sealed_loader.install()" not in (PY/"alvsia_bridge.py").read_text(errors="ignore"): fail.append("bridge does not install sealed loader")
if "ALVSIA_SEAL_SEED" not in (ROOT/"app/src/main/java/com/alvsia/pro/tool/ToolEngine.kt").read_text(errors="ignore"): fail.append("ToolEngine does not inject native seal seed")
if "nativeSealSeed" not in (ROOT/"app/src/main/java/com/alvsia/pro/sec/NativeGuard.kt").read_text(errors="ignore"): fail.append("Native seal seed JNI missing")
# Static controls for the VANTA review. These are source-level gates, not proof
# that external packers (Ark/ReArK/Virbox) were applied to a particular APK.
panel_file = JAVA / "com/alvsia/pro/panel/PanelClient.kt"
manifest_file = ROOT / "app/src/main/AndroidManifest.xml"
network_file = ROOT / "app/src/main/res/xml/network_security_config.xml"
gradle_file = ROOT / "app/build.gradle.kts"
proguard_file = ROOT / "app/proguard-rules.pro"
session_file = JAVA / "com/alvsia/pro/sec/SessionGate.kt"
audit_script = ROOT / "tools/audit_release_apk.py"
codemagic_file = ROOT / "codemagic.yaml"

def read_or_empty(path):
    try: return path.read_text(errors="ignore")
    except Exception: return ""

panel_text = read_or_empty(panel_file)
manifest_text = read_or_empty(manifest_file)
network_text = read_or_empty(network_file)
gradle_text = read_or_empty(gradle_file)
proguard_text = read_or_empty(proguard_file)
session_text = read_or_empty(session_file)

if not panel_text:
    fail.append("PanelClient.kt missing or unreadable")
else:
    if ".certificatePinner(Vault.certPinner())" not in panel_text:
        fail.append("OkHttp certificate pinning is not wired into PanelClient")
    if "clientPinned.newCall(req).execute()" not in panel_text:
        fail.append("PanelClient requests are not executed through the pinned client")
    for unsafe in ("clientLoose.newCall(req)", "callWithPinFallback", "handlePinFailure", "_pinGrace"):
        if unsafe in panel_text:
            fail.append("TLS pin downgrade/fallback remains in PanelClient: " + unsafe)

if "android.permission.DUMP" in manifest_text:
    fail.append("unneeded android.permission.DUMP is declared in the release manifest")
if "alvsiapro.cc.cd" not in network_text or "5xvRl/EyzQlZHSgU5dDZKbqmr+rFywWYzvSEEmJgC+Q=" not in network_text:
    fail.append("network security config is missing the expected panel domain/pin")
if '"/META-INF/version-control-info.textproto"' not in gradle_text and 'META-INF/version-control-info.textproto' not in gradle_text:
    fail.append("release packaging no longer excludes VCS revision metadata")
if "isMinifyEnabled = true" not in gradle_text:
    fail.append("release R8/minification is not enabled")
if "LineNumberTable" in proguard_text and "-keepattributes SourceFile,LineNumberTable" in proguard_text:
    fail.append("release ProGuard config retains line-number debug metadata")
if "KEY_ALGORITHM_HMAC_SHA256" not in session_text or "keystoreKey().encoded ?: byteArrayOf(0x42)" in session_text:
    fail.append("session strike integrity is not using a dedicated Android Keystore HMAC key")
if "now >= ts" not in session_text:
    fail.append("session TTL does not reject timestamps in the future")
if not audit_script.is_file():
    fail.append("release APK artifact audit script is missing")
if "python3 tools/audit_release_apk.py" not in read_or_empty(codemagic_file):
    fail.append("CodeMagic does not run the release APK artifact audit")

# A static native seal seed is recoverable by a sufficiently capable binary
# analyst. Do not block the build on this legacy format, but make the remaining
# limitation explicit rather than claiming that at-rest sealing is unbreakable.
native_text = read_or_empty(ROOT / "app/src/main/cpp/rasp_guard.cpp")
if "nativeSealSeed" in native_text and "static const unsigned char seed[32]" in native_text:
    warn.append("sealed Python payload key includes a build-static native seed; server-bound per-session/device keying remains unresolved")
if fail:
 print("SECURITY RELEASE CHECK: FAILED"); print("\n".join("- "+x for x in fail)); sys.exit(1)
print("SECURITY RELEASE CHECK: OK")
print("- protected Python source absent from release tree")
print(f"- sealed payloads: {len(sealed)}")
print("- native seed + live operation-grant gate wired")
if warn:
 print("SECURITY RELEASE CHECK: WARNINGS")
 for item in warn: print("- "+item)

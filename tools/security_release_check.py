#!/usr/bin/env python3
"""Source-level release gates for the ALVISIA PRO main-only sealed release pipeline."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "app/src/main/python"
JAVA = ROOT / "app/src/main/java/com/alvsia/pro"
fail = []

def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        fail.append(f"missing/unreadable: {path.relative_to(ROOT)}")
        return ""

gradle = read(ROOT / "app/build.gradle.kts")
manifest = read(ROOT / "app/src/main/AndroidManifest.xml")
panel = read(JAVA / "panel/PanelClient.kt")
vault = read(JAVA / "panel/Vault.kt")
session = read(JAVA / "sec/SessionGate.kt")
native = read(ROOT / "app/src/main/cpp/rasp_guard.cpp")
native_guard = read(JAVA / "sec/NativeGuard.kt")
tool_engine = read(JAVA / "tool/ToolEngine.kt")
bridge = read(PY / "alvsia_bridge.py")
loader = read(PY / "sealed_loader.py")
seal_script = read(ROOT / "tools/seal_python.py")
audit_script = read(ROOT / "tools/audit_release_apk.py")
codemagic = read(ROOT / "codemagic.yaml")
workflow = read(ROOT / ".github/workflows/android-validation.yml")

required_modules = {
    "alvsia_bridge_impl.py", "alvsia_core.py", "alvsia_ultimate.py",
    "alvsia_features.py", "lua_output_validator.py", "lua_string_recover.py",
    "lua_engine/engine.py", "lua_engine/decompiler53.py", "lua_engine/bgmi.py",
    "lua_engine/luajit_decompiler.py", "lua_engine/container.py",
    "lua_engine/detector.py", "lua_engine/multi_format.py",
    "lua_engine/vm_deobfuscator.py",
}
script_modules = set(re.findall(r'"([^"]+\.py)"', seal_script.split("MODULES = (",1)[-1].split(")",1)[0]))
loader_modules = set(re.findall(r'"([^"]+)":', loader.split("_MAP = {", 1)[-1].split("}", 1)[0]))
if required_modules - script_modules:
    fail.append("Python seal script misses modules: " + ", ".join(sorted(required_modules - script_modules)))
expected_loader = {p.removesuffix(".py").replace("/", ".") for p in required_modules}
if expected_loader - loader_modules:
    fail.append("sealed loader map misses modules: " + ", ".join(sorted(expected_loader - loader_modules)))
for rel in required_modules:
    if not (PY / rel).is_file():
        fail.append("protected source missing from developer/test tree: " + rel)
if "sealed_loader.install()" not in bridge or "ALVSIA_SEALED_RUNTIME" not in bridge:
    fail.append("bridge bootstrap does not install the sealed loader conditionally")
if "ALVSIA_SEAL_SEED" not in tool_engine or "NativeGuard.sealSeedHex()" not in tool_engine:
    fail.append("ToolEngine does not inject native seal seed after session validation")
if "nativeSealSeed" not in native_guard or "nativeSealSeed" not in native:
    fail.append("native seal seed JNI is not wired end-to-end")
if "AES/GCM/NoPadding" not in loader or "updateAAD(_MAGIC)" not in loader:
    fail.append("sealed loader lacks authenticated AES-GCM decryption")
if "ALVSEAL2" not in seal_script or "AESGCM" not in seal_script:
    fail.append("Python sealing script is missing authenticated encryption")
if "tools/seal_python.py --seal" not in codemagic or "tools/seal_python.py --restore" not in codemagic:
    fail.append("CodeMagic does not seal and restore protected Python modules")
if "tools/audit_release_apk.py" not in codemagic or "tools/audit_release_apk.py" not in workflow:
    fail.append("actual APK audit is not wired into both release pipelines")
if "CM_BRANCH" not in codemagic or '!= "main"' not in codemagic:
    fail.append("CodeMagic release branch is not restricted to main")
if "isMinifyEnabled = true" not in gradle or "isShrinkResources = true" not in gradle:
    fail.append("release R8/minification/resource shrinking is disabled")
if "META-INF/version-control-info.textproto" not in gradle:
    fail.append("VCS metadata is not excluded from release packaging")
if "android.permission.DUMP" in manifest:
    fail.append("unnecessary android.permission.DUMP remains in manifest")
if ".certificatePinner(Vault.certPinner())" not in panel or "clientPinned.newCall(req).execute()" not in panel:
    fail.append("PanelClient TLS certificate pinning is not wired")
if "networkSecurityConfig" not in manifest or "alvsiapro.cc.cd" not in read(ROOT / "app/src/main/res/xml/network_security_config.xml"):
    fail.append("panel network security configuration is missing")
if "KEY_ALGORITHM_HMAC_SHA256" not in session or "age in 0..SESSION_TTL" not in session:
    fail.append("SessionGate HMAC or future/expiry timestamp checks are missing")
if fail:
    print("SECURITY SOURCE CHECK: FAIL")
    print("\n".join("- " + x for x in fail))
    sys.exit(1)
print("SECURITY SOURCE CHECK: PASS")
print(f"- protected Python modules scheduled for sealing: {len(required_modules)}")
print("- AES-GCM loader + native seed bridge wired")
print("- TLS pinning, SessionGate HMAC/TTL, R8, VCS stripping checked")
print("- CodeMagic release restricted to main; APK audit required")
print("NOTE: native seed is build-bound obfuscation, not a server secret; runtime memory dumping remains possible.")

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
rasp_engine = read(JAVA / "sec/RaspEngine.kt")
tool_engine = read(JAVA / "tool/ToolEngine.kt")
bridge = read(PY / "alvsia_bridge.py")
loader = read(PY / "sealed_loader.py")
seal_script = read(ROOT / "tools/seal_python.py")
audit_script = read(ROOT / "tools/audit_release_apk.py")
codemagic = read(ROOT / "codemagic.yaml")
workflow = read(ROOT / ".github/workflows/android-validation.yml")
profile = read(ROOT / "app/src/main/java/com/alvsia/pro/ui/profile/ProfileScreen.kt")

required_modules = {
    "alvsia_bridge_impl.py", "alvsia_private.py", "alvsia_vm_protect.py", "lua_engine/pattern_registry.py",
    "alvsia_core.py", "alvsia_ultimate.py",
    "alvsia_ultimate_compat.py", "alvsia_features.py", "pinned_http.py",
    "lua_engine/lua_decompiler_final.py", "lua_engine/lua_protector.py",
    "lua_output_validator.py", "lua_string_recover.py",
    "lua_engine/engine.py", "lua_engine/decompiler53.py", "lua_engine/bgmi.py",
    "lua_engine/luajit_decompiler.py", "lua_engine/container.py",
    "lua_engine/detector.py", "lua_engine/multi_format.py",
    "lua_engine/streaming_decompiler.py", "lua_engine/vm_deobfuscator.py",
}
script_modules = set(re.findall(r'"([^"]+\.py)"', seal_script.split("MODULES = (",1)[-1].split(")",1)[0]))
loader_modules = set(re.findall(r'"([^"]+)":', loader.split("_MAP = {", 1)[-1].split("}", 1)[0]))
if required_modules - script_modules:
    fail.append("Python seal script misses modules: " + ", ".join(sorted(required_modules - script_modules)))
expected_loader = {p[:-3].replace("/", ".") for p in required_modules}
if expected_loader - loader_modules:
    fail.append("sealed loader map misses modules: " + ", ".join(sorted(expected_loader - loader_modules)))
if script_modules - required_modules:
    fail.append("seal script contains unreviewed modules: " + ", ".join(sorted(script_modules - required_modules)))
if loader_modules != expected_loader:
    fail.append("sealed loader inventory differs from required module inventory: missing=" +
                ", ".join(sorted(expected_loader - loader_modules)) + "; unexpected=" +
                ", ".join(sorted(loader_modules - expected_loader)))
if script_modules != required_modules:
    fail.append("seal script inventory differs from required module inventory")
for rel in required_modules:
    if not (PY / rel).is_file():
        fail.append("protected source missing from developer/test tree: " + rel)
if "sealed_loader.install()" not in bridge or "ALVSIA_SEALED_RUNTIME" not in bridge:
    fail.append("bridge bootstrap does not install the sealed loader conditionally")
if "def run_tool(" in bridge and "import alvsia_bridge_impl as impl" not in bridge:
    fail.append("plaintext bridge must delegate tool routing to the sealed implementation")
if len(bridge.encode("utf-8")) >= 2000 or "if mid == 1" in bridge:
    fail.append("plaintext bridge must remain a small stub without module-routing logic")
if "isTokenCurrent(token)" not in bridge:
    fail.append("bridge must compare the supplied token with the authoritative Kotlin session")
if "SessionGate.isSessionAuthorized()" not in loader:
    fail.append("sealed imports must check the live Kotlin session gate")
if "SessionGate.isSessionAuthorized()" not in read(PY / "alvsia_bridge_impl.py"):
    fail.append("sealed tool dispatch must check the live Kotlin session gate")
if "ALVSIA_SEAL_SEED" in tool_engine or "ALVSIA_SEAL_SEED" in loader:
    fail.append("seal seed must never be exposed through Python process environment")
if "sealBuildId()" not in loader or "_BUILD_ID" in loader or "_CERT_SHA256" in loader:
    fail.append("sealed loader must obtain its build ID natively and keep certificate digest out of Python")
if "fun sealBuildId(): String?" not in native_guard or "nativeSealBuildId" not in native:
    fail.append("sealed build ID must be provided through the native bridge")
if "fun decryptSealedPayload(payload: ByteArray, buildId: String)" not in native_guard or "nativeSealSeed()" not in native_guard:
    fail.append("Kotlin/native bridge must decrypt sealed payload without exposing the seed to Python")
if "ALVSIA_SEALED_RUNTIME" not in tool_engine:
    fail.append("ToolEngine does not enable sealed runtime after session validation")
if "nativeSealSeed" not in native_guard or "nativeSealSeed" not in native:
    fail.append("native seal seed JNI is not wired end-to-end")
if "AES/GCM/NoPadding" not in native_guard or "cipher.updateAAD(magic)" not in native_guard:
    fail.append("Kotlin/native bridge lacks authenticated AES-GCM decryption")
if "ALVSEAL2" not in seal_script or "AESGCM" not in seal_script:
    fail.append("Python sealing script is missing authenticated encryption")
if "tools/seal_python.py --seal" not in codemagic or "tools/seal_python.py --restore" not in codemagic:
    fail.append("CodeMagic does not seal and restore protected Python modules")
if "tools/audit_release_apk.py" not in codemagic or "tools/audit_release_apk.py" not in workflow:
    fail.append("actual APK audit is not wired into both release pipelines")
if "BuildConfig.VERSION_NAME" not in profile:
    fail.append("profile version label must use the actual built APK version")
if "rebrand_config.txt" not in audit_script or "app-metadata.properties" not in audit_script:
    fail.append("APK audit must reject packaged local rebrand/build metadata")
if "forbidden_inner" not in audit_script or "forbidden_package_names" not in audit_script:
    fail.append("APK audit must inspect nested Chaquopy app.imy metadata")
if "vm_extract_payload" not in audit_script or "Feistel-like" not in audit_script:
    fail.append("APK audit must scan plaintext code for exposed protection implementation markers")
if "CM_BRANCH" not in codemagic or '!= "main"' not in codemagic:
    fail.append("CodeMagic release branch is not restricted to main")
if "isMinifyEnabled = true" not in gradle or "isShrinkResources = true" not in gradle:
    fail.append("release R8/minification/resource shrinking is disabled")
if "-keepattributes SourceFile,LineNumberTable" in read(ROOT / "app/proguard-rules.pro"):
    fail.append("release ProGuard explicitly preserves source/line debug metadata")
if "-g0" not in read(ROOT / "app/src/main/cpp/CMakeLists.txt"):
    fail.append("native release build does not explicitly disable debug info")
if 'implementation("com.securevale:rasp-android:0.7.1")' in gradle:
    fail.append("recognizable SecureVale Android RASP SDK dependency remains")
if "SecureAppChecker" in rasp_engine or "com.securevale." in rasp_engine:
    fail.append("RaspEngine still references removed SecureVale SDK classes")
dual_vm = read(JAVA / "sec/DualVmGuard.kt")
if "DualVmGuard.inspect(ctx)" not in rasp_engine:
    fail.append("RaspEngine does not execute the dual-layer runtime integrity gate")
if "OP_PACKAGE" not in dual_vm or "OP_NATIVE" not in dual_vm or "dlrg_vm_bounds" not in dual_vm:
    fail.append("dual-layer runtime gate is missing bounded VM opcodes or native-stage checks")
if "NativeGuard.scanFlags()" not in dual_vm or "NativeGuard.dualVmNativeFlags()" not in dual_vm:
    fail.append("dual-layer runtime gate does not cross-check the native VM and native RASP scanner")
if "native_vm_flags" not in native or '"nativeVmFlags"' not in native or "fun dualVmNativeFlags()" not in native_guard:
    fail.append("native mini-VM JNI entry point is not wired end-to-end")
if 'SEED_ENV = "ALVSIA_SEAL_SEED_HEX"' not in seal_script:
    fail.append("Python sealing does not use the per-build seed environment variable")
if "secrets.token_hex(32)" not in workflow or "secrets.token_hex(32)" not in codemagic:
    fail.append("CI/CodeMagic do not generate a fresh per-build seal seed")
if "00112233445566778899aabbccddeeff" in native or "00112233445566778899aabbccddeeff" in seal_script:
    fail.append("fixed public seal seed remains in source")
if "META-INF/version-control-info.textproto" not in gradle or '"**/version-control-info.textproto"' not in gradle:
    fail.append("VCS metadata is not excluded from release packaging")
if "android.permission.DUMP" in manifest:
    fail.append("unnecessary android.permission.DUMP remains in manifest")
if ".certificatePinner(Vault.certPinner())" not in panel or "clientPinned.newCall(req).execute()" not in panel:
    fail.append("PanelClient TLS policy is not wired")
if ("networkSecurityConfig" not in manifest
        or "alvsiapanel.unaux.com" not in read(ROOT / "app/src/main/res/xml/network_security_config.xml")
        or "alvsiapanel.unaux.com" not in vault):
    fail.append("new-panel network security configuration is missing")
if "KEY_ALGORITHM_HMAC_SHA256" not in session or "age in 0..SESSION_TTL" not in session:
    fail.append("SessionGate HMAC or future/expiry timestamp checks are missing")
if "if (Guard.runtimeHostile(ctx))" not in session or "native_rasp_unavailable" not in session:
    fail.append("SessionGate must recheck live hooks each dispatch and fail closed if release JNI RASP is unavailable")
if "fun isNativeLoaded(): Boolean = nativeLoaded" not in native_guard:
    fail.append("NativeGuard load-state API is missing; release cannot detect JNI downgrade")
guard = read(JAVA / "sec/Guard.kt")
if "fun runtimeHostile(ctx: Context)" not in guard or "private val RUNTIME_MARKERS" not in guard:
    fail.append("Guard must distinguish active runtime instrumentation from root-only markers")
ultimate = read(PY / "alvsia_ultimate.py")
if "/SKIN_TOOL/main/SKIN_TOOL.zip" in ultimate or "/BGMI_CSV/main/" in ultimate:
    fail.append("external SKIN_TOOL/BGMI_CSV downloads are not commit-pinned")
if "_verify_pinned_git_blob" not in ultimate or "cbd3d0e257963b54f34a908b6864040c7f96fbb1" not in ultimate:
    fail.append("external data download integrity verification is missing")
if fail:
    print("SECURITY SOURCE CHECK: FAIL")
    print("\n".join("- " + x for x in fail))
    sys.exit(1)
print("SECURITY SOURCE CHECK: PASS")
print(f"- protected Python modules scheduled for sealing: {len(required_modules)}")
print("- AES-GCM decryption in Kotlin/native bridge; seed and cert digest not exposed to Python")
print("- New-panel TLS CA/hostname validation, SessionGate HMAC/TTL, R8, VCS stripping checked")
print("- CodeMagic release restricted to main; APK audit required")
print("NOTE: new-host SPKI pinning remains a release hardening gate until the live certificate chain is measured; native seed is build-bound obfuscation, not a server secret.")

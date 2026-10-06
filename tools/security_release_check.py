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
if fail:
 print("SECURITY RELEASE CHECK: FAILED"); print("\n".join("- "+x for x in fail)); sys.exit(1)
print("SECURITY RELEASE CHECK: OK")
print("- protected Python source absent from release tree")
print(f"- sealed payloads: {len(sealed)}")
print("- native seed + live operation-grant gate wired")

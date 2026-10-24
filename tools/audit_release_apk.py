#!/usr/bin/env python3
"""Audit the actual ALVISIA release APK for sealed Python/JAR payloads and metadata."""
from __future__ import annotations
import hashlib
import io
import re
import sys
import zipfile
from pathlib import Path

EXPECTED_SEALED = {
    "alvsia_bridge_impl.alv",
    "alvsia_core.alv",
    "alvsia_ultimate.alv",
    "alvsia_ultimate_compat.alv",
    "alvsia_features.alv",
    "pinned_http.alv",
    "lua_engine_lua_decompiler_final.alv",
    "lua_engine_lua_protector.alv",
    "lua_output_validator.alv",
    "lua_string_recover.alv",
    "lua_engine_engine.alv",
    "lua_engine_decompiler53.alv",
    "lua_engine_bgmi.alv",
    "lua_engine_luajit_decompiler.alv",
    "lua_engine_container.alv",
    "lua_engine_detector.alv",
    "lua_engine_multi_format.alv",
    "lua_engine_vm_deobfuscator.alv",
}
PROTECTED_MODULES = {
    "alvsia_bridge_impl", "alvsia_core", "alvsia_ultimate", "alvsia_ultimate_compat",
    "alvsia_features", "pinned_http", "lua_engine/lua_decompiler_final",
    "lua_engine/lua_protector",
    "lua_output_validator", "lua_string_recover",
    "lua_engine/engine", "lua_engine/decompiler53", "lua_engine/bgmi",
    "lua_engine/luajit_decompiler", "lua_engine/container", "lua_engine/detector",
    "lua_engine/multi_format", "lua_engine/vm_deobfuscator",
}
SEAL_MAGIC = b"ALVSEAL2"
ASSET_MAGIC = b"ALVSA1\x00"

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: audit_release_apk.py <release.apk>", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"FAIL APK not found: {apk}", file=sys.stderr)
        return 2
    report, failures = [], []
    def check(ok: bool, msg: str) -> None:
        report.append(("PASS " if ok else "FAIL ") + msg)
        if not ok:
            failures.append(msg)
    data = apk.read_bytes()
    report += [f"APK={apk}", f"SIZE={len(data)}", f"SHA256={hashlib.sha256(data).hexdigest()}"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            check(outer.testzip() is None, "APK ZIP integrity")
            names = set(outer.namelist())
            check("lib/arm64-v8a/librasp_guard.so" in names, "native RASP library packaged")
            check("assets/chaquopy/app.imy" in names, "Chaquopy app bundle packaged")
            check("assets/nx/i.dat" in names, "sealed JAR index packaged")
            check(not any(n.startswith("assets/unluac/") and n.lower().endswith(".jar") for n in names),
                  "plaintext unluac JAR assets absent")
            vcs_entries = sorted(n for n in names if n.endswith("version-control-info.textproto"))
            check(not vcs_entries, "VCS revision metadata absent" if not vcs_entries else "VCS revision metadata absent; found: " + ", ".join(vcs_entries))
            dex_names = sorted(n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n))
            dex_bytes = b"".join(outer.read(n) for n in dex_names)
            check(b"ALVISIA-20261010-MAIN-SEAL1" not in dex_bytes,
                  "sealed build ID absent from plaintext DEX")
            check(b"com/securevale/" not in dex_bytes,
                  "recognizable SecureVale SDK classes absent from DEX")
            manifest = outer.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
            check(bool(manifest), "compiled Android manifest exists")
            check(b"android.permission.DUMP" not in manifest,
                  "compiled manifest excludes android.permission.DUMP")
            # READ_PHONE_STATE is currently declared for legacy device/tool compatibility.
            # Do not fail the release audit merely because that declared permission is present;
            # any future permission removal must be verified against PermissionHelper/tool usage.
            report.append("INFO compiled manifest READ_PHONE_STATE presence recorded; permission policy is source-reviewed")
            blobs = sorted(n for n in names if n.startswith("assets/nx/") and n.endswith(".bin"))
            check(len(blobs) >= 3, f"sealed JAR asset count >= 3 (found {len(blobs)})")
            for n in blobs:
                check(outer.read(n).startswith(ASSET_MAGIC), f"sealed JAR header: {n}")
            index = outer.read("assets/nx/i.dat") if "assets/nx/i.dat" in names else b""
            check(index.startswith(ASSET_MAGIC), "sealed JAR index header")
            imy = outer.read("assets/chaquopy/app.imy") if "assets/chaquopy/app.imy" in names else b""
            try:
                with zipfile.ZipFile(io.BytesIO(imy)) as inner:
                    check(inner.testzip() is None, "Chaquopy app.imy ZIP integrity")
                    check(not any("version-control-info.textproto" in n for n in inner.namelist()), "VCS metadata absent from Chaquopy bundle")
                    members = inner.namelist()
                    by_base = {Path(n).name: n for n in members}
                    # The plaintext bridge is an authorization gate, not a tiny
                    # dispatcher stub. Validate its security contract rather than an
                    # arbitrary byte-size limit that varies with Python compilation.
                    bridge_name = next((n for n in members if re.fullmatch(r"alvsia_bridge(?:\.[a-z0-9_-]+)?\.pyc|alvsia_bridge\.py", Path(n).name)), None)
                    bridge_bytes = inner.read(bridge_name) if bridge_name else b""
                    check(bool(bridge_bytes), "plaintext authorization bridge packaged")
                    bridge_text = bridge_bytes.decode("utf-8", errors="ignore")
                    # Chaquopy may package the bridge as source or compiled .pyc.
                    # In bytecode, attribute access is represented as separate names
                    # ("impl" and "run_tool"), not the source substring "impl.run_tool".
                    compiled_bridge = bool(bridge_name and bridge_name.endswith(".pyc"))
                    required_bridge_contract = [
                        "configure_runtime", "isTokenCurrent", "ALVSIA_APK_SESSION",
                        "ALVSIA_SEALED_RUNTIME", "sealed_loader", "run_tool",
                        "isSessionAuthorized",
                    ]
                    required_bridge_contract.append("impl" if compiled_bridge else "impl.run_tool")
                    missing_bridge_contract = [token for token in required_bridge_contract if token not in bridge_text]
                    check(not missing_bridge_contract,
                          "bridge enforces session authorization and sealed delegation" if not missing_bridge_contract
                          else "bridge authorization/delegation contract missing: " + ", ".join(missing_bridge_contract))
                    check("if mid == 1" not in bridge_text and "elif mid == 1" not in bridge_text,
                          "tool routing is not shipped in plaintext bridge")
                    missing = sorted(EXPECTED_SEALED - set(by_base))
                    check(not missing, "all protected Python payloads exist" if not missing else "missing sealed payloads: " + ", ".join(missing))
                    for name in sorted(EXPECTED_SEALED & set(by_base)):
                        check(inner.read(by_base[name]).startswith(SEAL_MAGIC), f"AES-GCM payload header: {name}")
                    plaintext = []
                    for name in members:
                        normalized = name.replace("\\", "/").lower().lstrip("./")
                        base = Path(normalized).name
                        for module in PROTECTED_MODULES:
                            module = module.lower()
                            parent, _, leaf = module.rpartition("/")
                            source_match = (
                                base == leaf + ".py"
                                or base == leaf + ".pyc"
                                or re.fullmatch(re.escape(leaf) + r"\.[a-z0-9_-]+\.pyc", base) is not None
                            )
                            parent_match = not parent or ("/" + parent + "/") in ("/" + normalized + "/")
                            if source_match and parent_match:
                                plaintext.append(name)
                                break
                    check(not plaintext, "protected Python source/bytecode absent as plaintext" if not plaintext else "plaintext protected modules: " + ", ".join(plaintext))
                    check(any(Path(n).name in {"sealed_loader.py", "sealed_loader.pyc"} for n in members),
                          "sealed Python loader packaged")
            except (zipfile.BadZipFile, OSError) as exc:
                check(False, f"Chaquopy app.imy unreadable: {exc}")
    except (zipfile.BadZipFile, OSError) as exc:
        check(False, f"APK archive unreadable: {exc}")
    report.append("RESULT=" + ("FAIL" if failures else "PASS"))
    text = "\n".join(report) + "\n"
    print(text, end="")
    Path("release_security_audit.txt").write_text(text, encoding="utf-8")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())

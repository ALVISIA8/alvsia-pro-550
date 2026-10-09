#!/usr/bin/env python3
"""Audit the actual R5.4 release APK before it is offered as a CodeMagic artifact."""
from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path

EXPECTED_SEALED = {
    "alvsia_core.alv",
    "alvsia_features.alv",
    "alvsia_ultimate.alv",
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
    "alvsia_core",
    "alvsia_features",
    "alvsia_ultimate",
    "lua_output_validator",
    "lua_string_recover",
    "lua_engine/engine",
    "lua_engine/decompiler53",
    "lua_engine/bgmi",
    "lua_engine/luajit_decompiler",
    "lua_engine/container",
    "lua_engine/detector",
    "lua_engine/multi_format",
    "lua_engine/vm_deobfuscator",
}
SEAL_MAGIC = b"ALVSEAL2"
ASSET_MAGIC = b"ALVSA1\x00"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: audit_release_apk.py <release.apk>", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    report = []
    failures = []

    def check(ok: bool, message: str) -> None:
        report.append(("PASS " if ok else "FAIL ") + message)
        if not ok:
            failures.append(message)

    if not apk.is_file():
        print(f"FAIL APK not found: {apk}", file=sys.stderr)
        return 2

    apk_bytes = apk.read_bytes()
    report.append(f"APK={apk}")
    report.append(f"SIZE={len(apk_bytes)}")
    report.append(f"SHA256={hashlib.sha256(apk_bytes).hexdigest()}")

    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as outer:
            bad = outer.testzip()
            check(bad is None, "APK ZIP integrity")
            names = set(outer.namelist())
            check("lib/arm64-v8a/librasp_guard.so" in names, "native RASP library is packaged")
            check("assets/chaquopy/app.imy" in names, "Chaquopy app bundle is packaged")
            check("assets/nx/i.dat" in names, "sealed JAR index is packaged")
            check(
                not any(n.startswith("assets/unluac/") and n.lower().endswith(".jar") for n in names),
                "no plaintext unluac JAR under APK assets",
            )
            check(
                not any(n.endswith("META-INF/version-control-info.textproto") for n in names),
                "VCS revision metadata absent from APK",
            )

            for asset_name in sorted(n for n in names if n.startswith("assets/nx/") and n.endswith(".bin")):
                blob = outer.read(asset_name)
                check(blob.startswith(ASSET_MAGIC), f"sealed asset header: {asset_name}")
            index = outer.read("assets/nx/i.dat") if "assets/nx/i.dat" in names else b""
            check(index.startswith(ASSET_MAGIC), "sealed JAR index header")

            imy_data = outer.read("assets/chaquopy/app.imy") if "assets/chaquopy/app.imy" in names else b""
            try:
                with zipfile.ZipFile(io.BytesIO(imy_data)) as inner:
                    inner_bad = inner.testzip()
                    check(inner_bad is None, "Chaquopy app.imy ZIP integrity")
                    members = inner.namelist()
                    by_base = {Path(n).name: n for n in members}
                    missing = sorted(EXPECTED_SEALED - set(by_base))
                    check(not missing, "all 13 expected sealed Python modules exist" if not missing else "missing sealed modules: " + ", ".join(missing))

                    for basename in sorted(EXPECTED_SEALED & set(by_base)):
                        data = inner.read(by_base[basename])
                        check(data.startswith(SEAL_MAGIC), f"AES-GCM sealed module header: {basename}")

                    plaintext = []
                    for name in members:
                        normalized = name.replace("\\", "/")
                        lower = normalized.lower()
                        for module in PROTECTED_MODULES:
                            prefix = module.lower()
                            if lower in (prefix + ".py", prefix + ".pyc", prefix + ".pyc.pyc"):
                                plaintext.append(name)
                    check(not plaintext, "protected Python modules are not shipped as plaintext .py/.pyc" if not plaintext else "plaintext protected modules: " + ", ".join(plaintext))
            except (zipfile.BadZipFile, OSError) as exc:
                check(False, f"Chaquopy app.imy is not a readable ZIP: {exc}")
    except (zipfile.BadZipFile, OSError) as exc:
        report.append(f"FAIL APK archive cannot be read: {exc}")
        failures.append(str(exc))

    report.append("RESULT=" + ("FAIL" if failures else "PASS"))
    text = "\n".join(report) + "\n"
    print(text, end="")
    Path("release_security_audit.txt").write_text(text, encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

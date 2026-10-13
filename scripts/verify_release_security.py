#!/usr/bin/env python3
"""Fail-closed release audit for ALVSEAL2 Chaquopy payloads."""
from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path

APK = Path(sys.argv[1]) if len(sys.argv) > 1 else None
APP_IMY_SUFFIX = "assets/chaquopy/app.imy"
BUILD_PAYLOADS = {
    "alvsia_bridge_impl.alv", "alvsia_core.alv", "alvsia_ultimate.alv",
    "alvsia_ultimate_compat.alv", "alvsia_features.alv",
    "lua_output_validator.alv", "lua_string_recover.alv",
    "lua_engine_engine.alv", "lua_engine_decompiler53.alv",
    "lua_engine_bgmi.alv", "lua_engine_luajit_decompiler.alv",
    "lua_engine_container.alv", "lua_engine_detector.alv",
    "lua_engine_multi_format.alv", "lua_engine_vm_deobfuscator.alv",
}
PROTECTED_MODULES = {
    "alvsia_bridge_impl", "alvsia_core", "alvsia_ultimate",
    "alvsia_ultimate_compat", "alvsia_features",
    "lua_output_validator", "lua_string_recover",
    "lua_engine.engine", "lua_engine.decompiler53", "lua_engine.bgmi",
    "lua_engine.luajit_decompiler", "lua_engine.container",
    "lua_engine.detector", "lua_engine.multi_format",
    "lua_engine.vm_deobfuscator",
}


def fail(message: str) -> None:
    print("RELEASE SECURITY GATE: FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def module_from_archive_path(name: str) -> str | None:
    path = name.lower().replace("\\", "/")
    path = path.replace("/__pycache__/", "/")
    path = re.sub(r"\.cpython-[^/]+(?=\.pyc$)", "", path)
    if path.endswith(".pyc"):
        path = path[:-4]
    elif path.endswith(".py"):
        path = path[:-3]
    else:
        return None
    return path.replace("/", ".")


def main() -> None:
    if APK is None or not APK.is_file():
        fail("usage: verify_release_security.py /path/to/unsigned-release.apk")
    try:
        with zipfile.ZipFile(APK) as apk:
            matches = [n for n in apk.namelist() if n.endswith(APP_IMY_SUFFIX)]
            if len(matches) != 1:
                fail("expected exactly one " + APP_IMY_SUFFIX + "; found " + str(len(matches)))
            app_imy = apk.read(matches[0])
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        fail("cannot inspect APK/app.imy: " + str(exc))

    try:
        with zipfile.ZipFile(io.BytesIO(app_imy)) as runtime:
            names = runtime.namelist()
            alv = [n for n in names if n.lower().endswith(".alv")]
            actual = {n.rsplit("/", 1)[-1].lower() for n in alv}
            if actual != BUILD_PAYLOADS:
                fail("sealed payload inventory mismatch; missing=" +
                     ", ".join(sorted(BUILD_PAYLOADS - actual)) + "; unexpected=" +
                     ", ".join(sorted(actual - BUILD_PAYLOADS)))
            plaintext = []
            for name in names:
                module = module_from_archive_path(name)
                if module and any(module == expected or module.endswith("." + expected)
                                 for expected in PROTECTED_MODULES):
                    plaintext.append(name)
            if plaintext:
                fail("protected modules remain plaintext: " + ", ".join(plaintext))
            for name in alv:
                blob = runtime.read(name)
                if len(blob) < 36 or not blob.startswith(b"ALVSEAL2"):
                    fail("sealed payload header/length invalid: " + name)
    except (OSError, zipfile.BadZipFile) as exc:
        fail("app.imy is not a readable ZIP archive: " + str(exc))

    print("RELEASE SECURITY GATE: PASS: exact 15-payload inventory; authenticated-format headers; no protected plaintext")


if __name__ == "__main__":
    main()

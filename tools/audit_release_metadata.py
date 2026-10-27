#!/usr/bin/env python3
"""Fail release packaging if local-only rebrand or metadata files leak into APK assets."""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

FORBIDDEN_BASENAMES = {"rebrand_config.txt", "app-metadata.properties"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: audit_release_metadata.py <release.apk>", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"FAIL APK not found: {apk}", file=sys.stderr)
        return 2

    findings: list[str] = []
    try:
        with zipfile.ZipFile(apk) as outer:
            names = outer.namelist()
            for name in names:
                if Path(name.replace("\\", "/")).name.lower() in FORBIDDEN_BASENAMES:
                    findings.append("APK:" + name)
            inner_name = "assets/chaquopy/app.imy"
            if inner_name in names:
                try:
                    with zipfile.ZipFile(io.BytesIO(outer.read(inner_name))) as inner:
                        for name in inner.namelist():
                            if Path(name.replace("\\", "/")).name.lower() in FORBIDDEN_BASENAMES:
                                findings.append("app.imy:" + name)
                except zipfile.BadZipFile:
                    print("FAIL Chaquopy app.imy is not a valid ZIP archive", file=sys.stderr)
                    return 1
    except zipfile.BadZipFile:
        print("FAIL APK is not a valid ZIP archive", file=sys.stderr)
        return 1

    if findings:
        print("FAIL forbidden local configuration/metadata shipped:")
        print("\n".join(sorted(set(findings))))
        return 1
    print("PASS no rebrand_config.txt or app-metadata.properties in APK/app.imy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

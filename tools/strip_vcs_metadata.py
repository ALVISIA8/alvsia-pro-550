#!/usr/bin/env python3
"""Remove Gradle VCS revision metadata from an unsigned APK before audit/signing."""
from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from pathlib import Path

TARGET = "META-INF/version-control-info.textproto"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: strip_vcs_metadata.py <unsigned.apk>", file=sys.stderr)
        return 2

    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"FAIL APK not found: {apk}", file=sys.stderr)
        return 2

    fd, tmp_name = tempfile.mkstemp(prefix=apk.name + ".", suffix=".tmp", dir=str(apk.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    removed = 0
    try:
        with zipfile.ZipFile(apk, "r") as src:
            bad = src.testzip()
            if bad is not None:
                raise RuntimeError(f"input APK ZIP is corrupt at {bad}")
            with zipfile.ZipFile(tmp, "w") as dst:
                for info in src.infolist():
                    normalized = info.filename.replace("\\\\", "/")
                    if normalized.lower().endswith(TARGET.lower()):
                        removed += 1
                        continue
                    dst.writestr(info, src.read(info.filename))
        with zipfile.ZipFile(tmp, "r") as check:
            bad = check.testzip()
            if bad is not None:
                raise RuntimeError(f"rewritten APK ZIP is corrupt at {bad}")
            remaining = [n for n in check.namelist() if n.lower().endswith(TARGET.lower())]
            if remaining:
                raise RuntimeError("VCS metadata still present after rewrite")
        os.replace(tmp, apk)
        print(f"PASS unsigned APK VCS metadata stripped (entries removed: {removed})")
        print("APK will be zipaligned and signed after this step.")
        return 0
    except Exception as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        print(f"FAIL could not strip VCS metadata: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

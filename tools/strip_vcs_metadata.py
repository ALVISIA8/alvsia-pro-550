#!/usr/bin/env python3
"""Strip non-runtime metadata and plaintext rebrand template before APK audit/signing."""
from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from pathlib import Path

FORBIDDEN_BASENAMES = {
    "version-control-info.textproto",
    "app-metadata.properties",
    "rebrand_config.txt",
}


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
                dst.comment = src.comment
                for info in src.infolist():
                    normalized = info.filename.replace("\\", "/")
                    if Path(normalized).name.lower() in FORBIDDEN_BASENAMES:
                        removed += 1
                        continue
                    dst.writestr(info, src.read(info.filename))
        with zipfile.ZipFile(tmp, "r") as check:
            bad = check.testzip()
            if bad is not None:
                raise RuntimeError(f"rewritten APK ZIP is corrupt at {bad}")
            remaining = [
                n for n in check.namelist()
                if Path(n.replace("\\", "/")).name.lower() in FORBIDDEN_BASENAMES
            ]
            if remaining:
                raise RuntimeError("forbidden metadata remains after rewrite: " + ", ".join(remaining))
        os.replace(tmp, apk)
        print(f"PASS forbidden non-runtime metadata stripped (entries removed: {removed})")
        print("APK will be audited, zipaligned, and signed after this step.")
        return 0
    except Exception as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        print(f"FAIL could not strip forbidden metadata: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

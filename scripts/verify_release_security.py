#!/usr/bin/env python3
"""Release gate for the ALVISIA PRO sealed Python payload.

This is a fail-closed packaging check, not a claim that client-side secrets
can be made impossible to recover. Run against the unsigned release APK before
signing. Protected modules must be packaged only as authenticated .alv payloads.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

APK = Path(sys.argv[1]) if len(sys.argv) > 1 else None
PROTECTED_MODULES = {
    "alvsia_ultimate",
    "alvsia_core",
    "alvsia_ultimate_compat",
    "alvsia_bridge_impl",
}
APP_IMY_SUFFIX = "assets/chaquopy/app.imy"


def fail(message: str) -> None:
    print(f"RELEASE SECURITY GATE: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if APK is None or not APK.is_file():
        fail("usage: verify_release_security.py /path/to/unsigned-release.apk")

    try:
        with zipfile.ZipFile(APK) as apk:
            matches = [n for n in apk.namelist() if n.endswith(APP_IMY_SUFFIX)]
            if len(matches) != 1:
                fail(f"expected exactly one {APP_IMY_SUFFIX}; found {len(matches)}")
            app_imy_bytes = apk.read(matches[0])
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        fail(f"cannot inspect APK/app.imy: {exc}")

    import io
    try:
        with zipfile.ZipFile(io.BytesIO(app_imy_bytes)) as runtime:
            names = runtime.namelist()
            lower_names = [n.lower() for n in names]
            alv_files = [n for n in names if n.lower().endswith(".alv")]
            if not alv_files:
                fail("app.imy contains no .alv sealed payloads")
            plaintext = []
            for name in names:
                base = name.rsplit("/", 1)[-1].lower()
                if base.endswith((".py", ".pyc")):
                    stem = base.rsplit(".", 1)[0]
                    if stem in PROTECTED_MODULES:
                        plaintext.append(name)
            if plaintext:
                fail("protected modules remain plaintext: " + ", ".join(plaintext))
            # A marker alone is not sufficient: require a non-empty encrypted payload.
            for name in alv_files:
                if runtime.getinfo(name).file_size < 32:
                    fail(f"sealed payload is implausibly small: {name}")
    except (OSError, zipfile.BadZipFile) as exc:
        fail(f"app.imy is not a readable ZIP archive: {exc}")

    print(
        "RELEASE SECURITY GATE: PASS: "
        f"{len(alv_files)} non-empty .alv payload(s); "
        "protected plaintext modules absent"
    )


if __name__ == "__main__":
    main()

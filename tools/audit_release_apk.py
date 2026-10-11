#!/usr/bin/env python3
"""Audit the actual ALVISIA release APK for sealed Python/JAR payloads and metadata."""
from __future__ import annotations
import hashlib
import io
import re
import sys
import struct
import zipfile
from pathlib import Path

EXPECTED_SEALED = {
    "alvsia_bridge_impl.alv",
    "alvsia_core.alv",
    "alvsia_ultimate.alv",
    "alvsia_features.alv",
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
    "alvsia_bridge_impl", "alvsia_core", "alvsia_ultimate", "alvsia_features",
    "lua_output_validator", "lua_string_recover",
    "lua_engine/engine", "lua_engine/decompiler53", "lua_engine/bgmi",
    "lua_engine/luajit_decompiler", "lua_engine/container", "lua_engine/detector",
    "lua_engine/multi_format", "lua_engine/vm_deobfuscator",
}
SEAL_MAGIC = b"ALVSEAL2"
ASSET_MAGIC = b"ALVSA1\x00"

def android_xml_strings(data: bytes) -> set[str]:
    """Read the string pool from Android's compiled binary XML (AXML)."""
    if len(data) < 8 or data[:2] != b"\x03\x00":
        raise ValueError("not Android binary XML")
    offset = 8
    while offset + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or offset + chunk_size > len(data):
            raise ValueError("invalid AXML chunk bounds")
        if chunk_type == 0x0001:  # RES_STRING_POOL_TYPE
            if header_size < 28 or chunk_size < header_size:
                raise ValueError("invalid AXML string-pool header")
            string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
                "<IIIII", data, offset + 8
            )
            offsets_start = offset + header_size
            strings_base = offset + strings_start
            utf8 = bool(flags & 0x00000100)
            result: set[str] = set()

            def length8(pos: int) -> tuple[int, int]:
                first = data[pos]
                if first & 0x80:
                    return (((first & 0x7F) << 8) | data[pos + 1], pos + 2)
                return first, pos + 1

            def length16(pos: int) -> tuple[int, int]:
                first = struct.unpack_from("<H", data, pos)[0]
                if first & 0x8000:
                    second = struct.unpack_from("<H", data, pos + 2)[0]
                    return (((first & 0x7FFF) << 16) | second, pos + 4)
                return first, pos + 2

            for i in range(string_count):
                rel = struct.unpack_from("<I", data, offsets_start + i * 4)[0]
                pos = strings_base + rel
                if utf8:
                    _char_len, pos = length8(pos)
                    byte_len, pos = length8(pos)
                    end = pos + byte_len
                    if end > offset + chunk_size:
                        raise ValueError("AXML UTF-8 string exceeds string pool")
                    result.add(data[pos:end].decode("utf-8", errors="strict"))
                else:
                    char_len, pos = length16(pos)
                    end = pos + char_len * 2
                    if end > offset + chunk_size:
                        raise ValueError("AXML UTF-16 string exceeds string pool")
                    result.add(data[pos:end].decode("utf-16le", errors="strict"))
            return result
        offset += chunk_size
    raise ValueError("AXML string pool not found")

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
            check(not any(n.endswith("META-INF/version-control-info.textproto") for n in names),
                  "VCS revision metadata absent")
            dex_names = sorted(n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n))
            dex_bytes = b"".join(outer.read(n) for n in dex_names)
            check(b"com/securevale/" not in dex_bytes,
                  "recognizable SecureVale SDK classes absent from DEX")
            manifest = outer.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
            check(bool(manifest), "compiled Android manifest exists")
            if manifest:
                try:
                    manifest_strings = android_xml_strings(manifest)
                    check("android.permission.DUMP" not in manifest_strings,
                          "compiled manifest string pool excludes android.permission.DUMP")
                    check("android.permission.READ_PHONE_STATE" not in manifest_strings,
                          "compiled manifest string pool excludes android.permission.READ_PHONE_STATE")
                except (ValueError, UnicodeError, struct.error) as exc:
                    check(False, f"compiled Android manifest could not be parsed: {exc}")
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

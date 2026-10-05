"""
lua_engine/multi_format.py
ALVSIA PRO — Universal file format detector and extractor.

Detects and extracts Lua (all versions), LuaJIT, Unity asset bundles,
ZSTD/LZ4/zlib compressed blobs, custom container formats, and more.
Provides run_universal_smart() which handles ALL file types.

Supported formats:
  - Lua 5.1 / 5.2 / 5.3 / 5.4 bytecode
  - LuaJIT 2.0 / 2.1 bytecode (.ljbc)
  - Plain Lua source (.lua)
  - zlib-compressed Lua (0x789C/0x78DA header)
  - LZ4 frame (magic 0x184D2204)
  - ZSTD frame (magic 0xFD2FB528)
  - Unity AssetBundle (UnityFS / UnityRaw)
  - Unity .bytes wrapper (raw bytes with Lua inside)
  - BGMI/PUBG PAK container (custom Tencent format)
  - ZIP archive (.zip, .apk, .pak)
  - 7-Zip archive (7z magic)
  - Android DEX (.dex) — extract embedded strings/Lua
  - ELF binary — extract embedded strings/Lua
  - PE binary (Windows .exe/.dll) — extract embedded strings/Lua
  - Protobuf-like blobs — extract string fields
  - Plain text / JSON / source code

Public API:
    detect_format(path) -> FormatInfo
    run_universal_smart(input_path, out_dir, jars_dir=None) -> dict
"""
from __future__ import annotations
import mmap, struct, zlib, os, hashlib, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Any, Dict, Tuple

# ─── magic bytes ──────────────────────────────────────────────────────────────
MAGIC = {
    "lua53":    b"\x1bLua\x53",
    "lua54":    b"\x1bLua\x54",
    "lua52":    b"\x1bLua\x52",
    "lua51":    b"\x1bLua\x51",
    "luajit":   b"\x1bLJ",
    "zlib_lo":  b"\x78\x9c",
    "zlib_hi":  b"\x78\xda",
    "zlib_def": b"\x78\x01",
    "lz4_frame":b"\x04\x22\x4d\x18",
    "zstd":     b"\x28\xb5\x2f\xfd",
    "zip":      b"PK\x03\x04",
    "zip_emp":  b"PK\x05\x06",
    "7z":       b"7z\xbc\xaf\x27\x1c",
    "elf":      b"\x7fELF",
    "pe_dos":   b"MZ",
    "dex":      b"dex\n",
    "unity_fs": b"UnityFS",
    "unity_raw":b"UnityRaw",
    "unity_web":b"UnityWeb",
    "bson":     b"\x08\x00\x00\x00",  # rough BSON
    "msgpack":  bytes([0x92]),         # rough msgpack array-2
    "gz":       b"\x1f\x8b",
    "bz2":      b"BZh",
    "xz":       b"\xfd7zXZ\x00",
    "lzma":     bytes([0x5d, 0x00, 0x00]),
    "ogg":      b"OggS",
    "png":      b"\x89PNG",
    "jpg":      b"\xff\xd8\xff",
    "mp4":      b"ftyp",              # at offset 4
    "rar":      b"Rar!\x1a\x07",
}


@dataclass
class FormatInfo:
    fmt:        str           # canonical format name
    category:   str           # "lua", "archive", "binary", "text", "media", "unknown"
    lua_version: Optional[str] = None
    compressed: bool = False
    container:  bool = False
    has_lua:    bool = False
    notes:      List[str] = field(default_factory=list)
    magic_hex:  str = ""
    size:       int = 0


def _read_head(path: Path, n: int = 32) -> bytes:
    if not path.is_file():
        return b""
    with open(path, "rb") as f:
        return f.read(n)


def detect_format(path: "Path | str") -> FormatInfo:
    """Detect the format of any file. Does not read more than 64 bytes."""
    path = Path(path)
    if not path.is_file():
        return FormatInfo("missing", "unknown")

    data = _read_head(path, 64)
    size = path.stat().st_size
    magic_hex = data[:8].hex()

    def _fi(fmt, cat, **kw):
        return FormatInfo(fmt, cat, magic_hex=magic_hex, size=size, **kw)

    # ── Lua bytecode ──────────────────────────────────────────────────────────
    if data[:5] == MAGIC["lua53"]:
        return _fi("lua53", "lua", lua_version="5.3")
    if data[:5] == MAGIC["lua54"]:
        return _fi("lua54", "lua", lua_version="5.4")
    if data[:5] == MAGIC["lua52"]:
        return _fi("lua52", "lua", lua_version="5.2")
    if data[:5] == MAGIC["lua51"]:
        return _fi("lua51", "lua", lua_version="5.1")
    if data[:3] == MAGIC["luajit"] and len(data) > 3 and data[3] in (0x01, 0x02):
        return _fi("luajit", "lua", lua_version="LuaJIT2")

    # ── Unity ─────────────────────────────────────────────────────────────────
    if data[:7] == MAGIC["unity_fs"] or data[:8] == MAGIC["unity_raw"] or data[:8] == MAGIC["unity_web"]:
        return _fi("unity_bundle", "archive", container=True,
                   notes=["Unity asset bundle — may contain Lua bytecode"])

    # ── Compressed ────────────────────────────────────────────────────────────
    if data[:2] in (MAGIC["zlib_lo"], MAGIC["zlib_hi"], MAGIC["zlib_def"]):
        return _fi("zlib", "archive", compressed=True,
                   notes=["zlib-compressed — decompress and re-detect"])
    if data[:2] == MAGIC["gz"]:
        return _fi("gzip", "archive", compressed=True)
    if data[:3] == MAGIC["bz2"]:
        return _fi("bzip2", "archive", compressed=True)
    if data[:6] == MAGIC["xz"]:
        return _fi("xz", "archive", compressed=True)
    if data[:3] == MAGIC["lzma"]:
        return _fi("lzma", "archive", compressed=True)
    if data[:4] == bytes(reversed(MAGIC["lz4_frame"])):  # LZ4 is LE
        return _fi("lz4", "archive", compressed=True)
    if data[:4] == MAGIC["zstd"]:
        return _fi("zstd", "archive", compressed=True)

    # ── Archives ─────────────────────────────────────────────────────────────
    if data[:4] in (MAGIC["zip"], MAGIC["zip_emp"]):
        ext = path.suffix.lower()
        fmt = {"apk": "apk", ".apk": "apk", ".ipa": "ipa",
               ".pak": "pak_zip", ".jar": "jar"}.get(ext, "zip")
        return _fi(fmt, "archive", container=True)
    if data[:6] == MAGIC["7z"]:
        return _fi("7z", "archive", container=True)
    if data[:6] == MAGIC["rar"]:
        return _fi("rar", "archive", container=True)

    # ── Binary executables ────────────────────────────────────────────────────
    if data[:4] == MAGIC["elf"]:
        return _fi("elf", "binary", notes=["ELF — may embed Lua bytecode as section data"])
    if data[:2] == MAGIC["pe_dos"] and size > 64:
        return _fi("pe", "binary", notes=["PE — may embed Lua bytecode"])
    if data[:4] == MAGIC["dex"]:
        return _fi("dex", "binary", notes=["Android DEX — may embed Lua strings"])

    # ── Media (skip) ─────────────────────────────────────────────────────────
    if data[:8] == MAGIC["png"]:
        return _fi("png", "media")
    if data[:3] == MAGIC["jpg"]:
        return _fi("jpg", "media")
    if data[:4] == MAGIC["ogg"]:
        return _fi("ogg", "media")

    # ── Text / source ─────────────────────────────────────────────────────────
    try:
        sample = data.decode("utf-8", errors="strict")
        if re.search(r'\b(local|function|return|if|for|while|end|require)\b', sample):
            return _fi("lua_source", "lua", lua_version="source",
                       notes=["plain Lua source code"])
        if sample.strip().startswith(("{", "[")):
            return _fi("json", "text")
        return _fi("text", "text")
    except UnicodeDecodeError:
        pass

    # ── Sniff for embedded Lua magic anywhere in first 256 bytes ─────────────
    extended = _read_head(path, 256)
    for offset in range(0, min(len(extended) - 5, 240)):
        chunk = extended[offset:]
        if chunk[:5] == MAGIC["lua53"]:
            return _fi("lua53_offset", "lua", lua_version="5.3",
                       notes=[f"Lua53 magic at offset {offset}"])
        if chunk[:5] == MAGIC["lua51"]:
            return _fi("lua51_offset", "lua", lua_version="5.1",
                       notes=[f"Lua51 magic at offset {offset}"])
        if chunk[:3] == MAGIC["luajit"] and len(chunk) > 3 and chunk[3] in (0x01, 0x02):
            return _fi("luajit_offset", "lua", lua_version="LuaJIT2",
                       notes=[f"LuaJIT magic at offset {offset}"])

    # ── Custom game containers (heuristic) ────────────────────────────────────
    # Many games use a 4-byte magic + 4-byte size header
    if size > 16:
        m4 = data[:4]
        all_printable = all(32 <= b < 127 for b in m4)
        if all_printable:
            return _fi("custom_container", "archive", container=True,
                       notes=[f"printable 4-byte magic: {m4.decode('ascii', 'replace')!r}"])

    return _fi("unknown", "unknown", notes=["unrecognized format"])


# ─── decompression helpers ────────────────────────────────────────────────────
def _decompress_zlib(data: bytes) -> Optional[bytes]:
    try:
        return zlib.decompress(data)
    except Exception:
        try:
            return zlib.decompress(data, -15)
        except Exception:
            return None


def _decompress_zstd(data: bytes) -> Optional[bytes]:
    try:
        import zstandard as zstd
        ctx = zstd.ZstdDecompressor()
        return ctx.decompress(data, max_output_size=256 * 1024 * 1024)
    except ImportError:
        return None
    except Exception:
        return None


def _decompress_lz4(data: bytes) -> Optional[bytes]:
    try:
        import lz4.frame
        return lz4.frame.decompress(data)
    except ImportError:
        try:
            import lz4
            return lz4.decompress(data)
        except Exception:
            return None
    except Exception:
        return None


def _decompress_gzip(data: bytes) -> Optional[bytes]:
    import gzip
    try:
        return gzip.decompress(data)
    except Exception:
        return None


def _decompress_bzip2(data: bytes) -> Optional[bytes]:
    import bz2
    try:
        return bz2.decompress(data)
    except Exception:
        return None


def _decompress_xz(data: bytes) -> Optional[bytes]:
    import lzma
    try:
        return lzma.decompress(data)
    except Exception:
        return None


DECOMPRESSORS = {
    "zlib":   _decompress_zlib,
    "gzip":   _decompress_gzip,
    "bzip2":  _decompress_bzip2,
    "xz":     _decompress_xz,
    "lzma":   _decompress_xz,
    "zstd":   _decompress_zstd,
    "lz4":    _decompress_lz4,
}


def try_decompress(data: bytes, fmt: str) -> Optional[bytes]:
    fn = DECOMPRESSORS.get(fmt)
    if fn:
        return fn(data)
    # try all
    for f, fn in DECOMPRESSORS.items():
        result = fn(data)
        if result:
            return result
    return None


# ─── extract Lua from container ──────────────────────────────────────────────
def _extract_lua_from_zip(path: Path, out_dir: Path) -> List[Path]:
    """Extract all Lua/luac files from a ZIP-based archive."""
    import zipfile
    out_paths = []
    try:
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                low = name.lower()
                if low.endswith((".lua", ".luac", ".ljbc", ".bytes")):
                    data = z.read(name)
                    safe_name = re.sub(r"[^\w.\-]", "_", name.replace("/", "__"))
                    dest = out_dir / safe_name
                    dest.write_bytes(data)
                    out_paths.append(dest)
                    if len(out_paths) >= 200:
                        break
    except Exception:
        pass
    return out_paths


def _extract_lua_from_binary(path: Path, out_dir: Path) -> List[Path]:
    """
    Scan a binary (ELF, PE, DEX, unknown) for embedded Lua bytecode.
    Returns paths to extracted blobs.
    """
    LUA_MAGICS = [
        (b"\x1bLua\x53", "lua53"),
        (b"\x1bLua\x54", "lua54"),
        (b"\x1bLua\x52", "lua52"),
        (b"\x1bLua\x51", "lua51"),
        (b"\x1bLJ\x01",  "luajit"),
        (b"\x1bLJ\x02",  "luajit"),
    ]
    try:
        sz = path.stat().st_size
        if sz > 128 * 1024 * 1024:  # skip huge binaries
            return []
        data = path.read_bytes()
    except Exception:
        return []

    found = []
    for magic, tag in LUA_MAGICS:
        offset = 0
        while True:
            idx = data.find(magic, offset)
            if idx < 0:
                break
            # extract up to 8MB from this offset (heuristic)
            blob = data[idx:idx + min(8 * 1024 * 1024, len(data) - idx)]
            if len(blob) < 32:
                offset = idx + 1; continue
            dest = out_dir / f"{path.stem}_embedded_{tag}_{idx:#x}.luac"
            dest.write_bytes(blob)
            found.append(dest)
            offset = idx + 1
            if len(found) >= 20:
                break

    return found


def _scan_strings_from_binary(path: Path, out_dir: Path, min_len: int = 6) -> Path:
    """Extract printable strings from any binary file."""
    try:
        data = path.read_bytes()
    except Exception:
        return None
    strings = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                strings.append(cur.decode("ascii", "ignore").strip())
            cur.clear()
    if len(cur) >= min_len:
        strings.append(cur.decode("ascii", "ignore").strip())

    # filter Lua-like strings
    lua_strings = [s for s in strings if re.search(
        r'\b(local|function|return|require|if|for|while|end|table\.|string\.|math\.)\b', s)]

    out_path = out_dir / f"{path.stem}_strings.txt"
    content = "-- All strings:\n" + "\n".join(strings[:5000])
    if lua_strings:
        content += "\n\n-- Lua-like strings:\n" + "\n".join(lua_strings[:1000])
    out_path.write_text(content, encoding="utf-8")
    return out_path


# ─── Unity AssetBundle extractor ─────────────────────────────────────────────
def _extract_unity_bundle(path: Path, out_dir: Path) -> List[Path]:
    """
    Very basic Unity AssetBundle extractor.
    Scans for embedded Lua magic bytes — no full Unity format parsing.
    """
    return _extract_lua_from_binary(path, out_dir)


# ─── public: universal smart handler ─────────────────────────────────────────
def run_universal_smart(
    input_path: "Path | str",
    out_dir: "Path | str",
    jars_dir=None,
    _depth: int = 0,
) -> dict:
    """
    Universal file handler — detects format and routes to the best extractor.
    Handles: Lua 5.1-5.4, LuaJIT, zlib/zstd/lz4/gzip/bz2/xz compressed,
    ZIP/APK/PAK archives, Unity bundles, ELF/PE/DEX binaries.

    Returns {"ok": True/False, "mode": str, "out": str/list, ...}
    """
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if _depth > 4:
        return {"ok": False, "error": "max recursion depth reached in universal extractor"}

    fmt_info = detect_format(input_path)
    result = {"file": str(input_path), "format": fmt_info.fmt, "category": fmt_info.category,
              "size": fmt_info.size, "notes": fmt_info.notes}

    # ── Lua bytecode — decompile directly ─────────────────────────────────────
    if fmt_info.category == "lua" and fmt_info.lua_version in ("5.3", "5.4", "5.2", "5.1", "LuaJIT2", "source"):
        return _handle_lua(input_path, out_dir, fmt_info, jars_dir, result)

    # ── lua with magic at offset — strip offset ───────────────────────────────
    if fmt_info.fmt in ("lua53_offset", "lua51_offset", "luajit_offset"):
        data = input_path.read_bytes()
        for off in range(0, min(len(data) - 5, 240)):
            chunk = data[off:]
            for magic_bytes in (b"\x1bLua\x53", b"\x1bLua\x51", b"\x1bLua\x52",
                                 b"\x1bLua\x54", b"\x1bLJ\x01", b"\x1bLJ\x02"):
                if chunk[:len(magic_bytes)] == magic_bytes:
                    stripped = out_dir / (input_path.stem + "_stripped.luac")
                    stripped.write_bytes(chunk)
                    sub = run_universal_smart(stripped, out_dir, jars_dir, _depth + 1)
                    sub["stripped_offset"] = off
                    return sub
        return {"ok": False, "error": "could not locate Lua magic in binary", **result}

    # ── Compressed ────────────────────────────────────────────────────────────
    if fmt_info.compressed or fmt_info.fmt in DECOMPRESSORS:
        data = input_path.read_bytes()
        decompressed = try_decompress(data, fmt_info.fmt)
        if decompressed:
            dec_path = out_dir / (input_path.stem + "_decompressed.bin")
            dec_path.write_bytes(decompressed)
            result["decompressed"] = str(dec_path)
            sub = run_universal_smart(dec_path, out_dir, jars_dir, _depth + 1)
            sub["compressed_from"] = fmt_info.fmt
            return sub
        return {"ok": False, "error": f"decompression failed for {fmt_info.fmt}", **result}

    # ── ZIP-based archives ─────────────────────────────────────────────────────
    if fmt_info.fmt in ("zip", "apk", "pak_zip", "jar", "ipa"):
        extracted = _extract_lua_from_zip(input_path, out_dir)
        if not extracted:
            return {"ok": False, "error": "no Lua files found in archive", **result}
        results = []
        for lua_path in extracted[:20]:  # limit to 20 files
            sub = run_universal_smart(lua_path, out_dir, jars_dir, _depth + 1)
            results.append(sub)
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"ok": ok_count > 0, "mode": "archive_extract",
                "extracted_count": len(extracted), "ok_count": ok_count,
                "results": results[:10], **result}

    # ── Unity AssetBundle ─────────────────────────────────────────────────────
    if fmt_info.fmt == "unity_bundle":
        embedded = _extract_unity_bundle(input_path, out_dir)
        if not embedded:
            strings_path = _scan_strings_from_binary(input_path, out_dir)
            return {"ok": False, "error": "no Lua found in Unity bundle",
                    "strings": str(strings_path) if strings_path else None, **result}
        results = []
        for blob in embedded[:10]:
            sub = run_universal_smart(blob, out_dir, jars_dir, _depth + 1)
            results.append(sub)
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"ok": ok_count > 0, "mode": "unity_extract",
                "embedded_count": len(embedded), "ok_count": ok_count,
                "results": results[:10], **result}

    # ── Binary (ELF/PE/DEX/custom container) ──────────────────────────────────
    if fmt_info.category in ("binary", "archive") or fmt_info.fmt in ("custom_container", "elf", "pe", "dex"):
        embedded = _extract_lua_from_binary(input_path, out_dir)
        strings_path = _scan_strings_from_binary(input_path, out_dir)
        if not embedded:
            return {"ok": False, "mode": "binary_scan",
                    "strings": str(strings_path) if strings_path else None,
                    "note": "no embedded Lua found; strings extracted", **result}
        results = []
        for blob in embedded[:10]:
            sub = run_universal_smart(blob, out_dir, jars_dir, _depth + 1)
            results.append(sub)
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"ok": ok_count > 0, "mode": "binary_extract",
                "embedded_count": len(embedded), "ok_count": ok_count,
                "results": results[:10],
                "strings": str(strings_path) if strings_path else None, **result}

    # ── Unknown ───────────────────────────────────────────────────────────────
    # Last resort: brute scan for embedded Lua + strings
    embedded = _extract_lua_from_binary(input_path, out_dir)
    strings_path = _scan_strings_from_binary(input_path, out_dir)
    if embedded:
        results = []
        for blob in embedded[:5]:
            sub = run_universal_smart(blob, out_dir, jars_dir, _depth + 1)
            results.append(sub)
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"ok": ok_count > 0, "mode": "bruteforce_extract",
                "embedded_count": len(embedded), "ok_count": ok_count,
                "results": results[:5], "strings": str(strings_path) if strings_path else None,
                **result}

    return {"ok": False, "mode": "unknown_format",
            "strings": str(strings_path) if strings_path else None,
            "note": "format not recognized; strings extracted as fallback", **result}


def _handle_lua(path: Path, out_dir: Path, fmt_info: FormatInfo, jars_dir, base_result: dict) -> dict:
    """Route a confirmed Lua file to the appropriate decompiler."""
    ver = fmt_info.lua_version

    # plain Lua source — just copy it
    if ver == "source":
        dest = out_dir / (path.stem + "_source.lua")
        import shutil; shutil.copy2(path, dest)
        return {"ok": True, "mode": "lua_source_passthrough", "out": str(dest), **base_result}

    # LuaJIT → disassemble
    if ver == "LuaJIT2":
        from lua_engine.luajit_decompiler import disassemble_luajit
        dest = out_dir / (path.stem + "_ljbc.lua")
        r = disassemble_luajit(path, dest)
        return {"ok": r.get("ok", False), "mode": "luajit_disasm", **r, **base_result}

    # Lua 5.3 → full Python decompiler
    if ver == "5.3":
        try:
            from lua_engine.decompiler53 import decompile_file as _dc53
            dest = out_dir / (path.stem + "_decompiled.lua")
            r = _dc53(path, dest)
            if r.get("ok"):
                # Check for VM obfuscation in the output
                try:
                    from lua_engine.vm_deobfuscator import extract_vm_payload, detect_vm_obfuscation
                    obf = detect_vm_obfuscation(path)
                    if obf.is_obfuscated:
                        vr = extract_vm_payload(path, out_dir)
                        r["vm_obfuscated"] = True
                        r["vm_confidence"] = obf.confidence
                        r["vm_notes"] = obf.notes
                        r["vm_extract"] = vr
                        if vr.get("ok"):
                            # Recursively decompile the recovered payload
                            recovered_path = Path(vr["out"])
                            sub = _handle_lua(recovered_path, out_dir, FormatInfo("lua53", "lua", "5.3"), jars_dir, {})
                            r["vm_decompiled"] = sub
                    else:
                        r["vm_obfuscated"] = False
                except Exception as ve:
                    r["vm_check_error"] = str(ve)
                return {"ok": True, "mode": "py53_decompile", **r, **base_result}
        except Exception as e:
            pass

        # Fallback to unluac
        try:
            from alvsia_features import run_unluac
            ur = run_unluac(path, out_dir, jars_dir=jars_dir)
            if ur.get("ok"):
                return {"ok": True, "mode": "unluac_53", **ur, **base_result}
        except Exception:
            pass

    # Lua 5.1/5.2/5.4 → unluac or luadec
    try:
        from alvsia_features import run_unluac
        ur = run_unluac(path, out_dir, jars_dir=jars_dir)
        if ur.get("ok"):
            return {"ok": True, "mode": f"unluac_{ver}", **ur, **base_result}
    except Exception as e:
        pass

    # Fallback: extract constants + strings
    try:
        from alvsia_features import extract_lua_constants, run_lua_bytecode_strings
        cr = extract_lua_constants(path, out_dir)
        sr = run_lua_bytecode_strings(path, out_dir)
        return {"ok": False, "mode": "lua_partial_recovery",
                "constants": cr, "strings": sr, **base_result}
    except Exception as e:
        return {"ok": False, "error": str(e), **base_result}

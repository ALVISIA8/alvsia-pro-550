# -*- coding: utf-8 -*-
"""ALVISIA PRO — output validator (anti fake-success).

SUCCESS decompile hanya jika teks lolos heuristik source Lua.
File > 0 byte BUKAN sukses.
"""
from __future__ import annotations
from pathlib import Path
import re

LUA_SOURCE_MARKERS = (
    r"\bfunction\b",
    r"\blocal\s+\w",
    r"\brequire\s*\(",
    r"\bend\b",
    r"\breturn\b",
)
LUA_BC_MAGICS = (b"\x1bLua", b"\x1bLJ")


def classify_bytes(data: bytes) -> dict:
    info = {
        "size": len(data),
        "head_hex": data[:16].hex() if data else "",
        "format": "unknown",
        "confidence": "low",
        "lua_version_hint": None,
    }
    if not data:
        info["format"] = "empty"
        return info
    if data.startswith(b"--") or data.lstrip()[:8].lower().startswith(b"function") or b"local " in data[:200]:
        info["format"] = "plain_lua_source"
        info["confidence"] = "medium"
        return info
    if data.startswith(b"\x1bLuaS"):
        info["format"] = "luaS_bytecode"
        info["lua_version_hint"] = "5.3-custom" if len(data) > 4 and data[4] == 0x53 else "unknown"
        info["confidence"] = "high"
        return info
    if data.startswith(b"\x1bLua"):
        ver = data[4] if len(data) > 4 else 0
        info["format"] = "lua_bytecode"
        info["lua_version_hint"] = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}.get(ver, hex(ver))
        info["confidence"] = "high"
        return info
    if data.startswith(b"\x1bLJ"):
        info["format"] = "luajit_bytecode"
        info["confidence"] = "high"
        return info
    if data[:2] == b"\x78\xda" or data[:2] == b"\x78\x9c":
        info["format"] = "zlib_container"
        info["confidence"] = "high"
        return info
    if data[:2] == b"\x1f\x8b":
        info["format"] = "gzip"
        info["confidence"] = "high"
        return info
    if data[:2] == b"PK":
        info["format"] = "zip"
        info["confidence"] = "high"
        return info
    return info


def looks_like_lua_source(text: str) -> bool:
    if not text or len(text) < 20:
        return False
    hits = sum(1 for pat in LUA_SOURCE_MARKERS if re.search(pat, text))
    # butuh minimal 2 marker berbeda
    return hits >= 2


def validate_decompile_text(text: str) -> dict:
    ok = looks_like_lua_source(text)
    return {
        "status": "SUCCESS" if ok else "PARTIAL" if text.strip() else "FAILED",
        "is_lua_source": ok,
        "size": len(text),
        "reason": "heuristic source markers" if ok else "no lua source markers (not a decompile)",
    }


def validate_path(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"status": "INVALID_INPUT", "reason": "missing file", "path": path}
    data = p.read_bytes()
    det = classify_bytes(data)
    # if text-ish, also validate as source
    try:
        text = data.decode("utf-8")
    except Exception:
        text = ""
    dec = validate_decompile_text(text) if text and det["format"] in ("plain_lua_source", "unknown") else None
    return {"status": "OK_DETECT", "detect": det, "decompile_validate": dec, "path": path}


if __name__ == "__main__":
    import json, sys
    for a in sys.argv[1:]:
        print(json.dumps(validate_path(a), indent=2))

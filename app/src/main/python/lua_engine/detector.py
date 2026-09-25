from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import re

LUA_MAGICS = {b"\x1bLua"}
LUA_VERSIONS = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}

@dataclass(frozen=True)
class LuaInfo:
    kind: str
    version: str | None
    format: str
    size: int
    magic: str
    confidence: float
    notes: tuple[str, ...] = ()

    def to_dict(self):
        d = asdict(self)
        d["notes"] = list(self.notes)
        return d

def detect_bytes(data: bytes) -> LuaInfo:
    size = len(data)
    magic = data[:8].hex()
    if data.startswith(b"\x1bLJ"):
        ver = "LuaJIT 2.0/2.1"
        if len(data) >= 3 and data[2] == 2:
            ver = "LuaJIT 2.1"
        return LuaInfo("bytecode", ver, "luajit", size, magic, 0.99)
    if data.startswith(b"\x1bLua"):
        vb = data[4] if len(data) > 4 else 0
        version = LUA_VERSIONS.get(vb)
        if version:
            return LuaInfo("bytecode", f"Lua {version}", "luac", size, magic, 0.99)
        return LuaInfo("bytecode", None, "luac-unknown", size, magic, 0.90,
                       ("Lua magic present but version byte is unknown",))
    # Text Lua is deliberately heuristic: require a plausible token and avoid
    # classifying arbitrary binary blobs containing "function".
    head = data[:8192].decode("utf-8", "ignore")
    stripped = head.lstrip("\ufeff \t\r\n")
    if re.search(r"^(?:#!.*\n\s*)?(?:local|return|function|if|for|while|repeat|do)\b", stripped):
        return LuaInfo("source", None, "lua-source", size, magic, 0.85)
    if b"function" in data[:4096] and all((b in (9,10,13) or 32 <= b < 127) for b in data[:4096]):
        return LuaInfo("source", None, "lua-source", size, magic, 0.70)
    return LuaInfo("unknown", None, "unknown", size, magic, 0.0)

def detect_lua(path) -> LuaInfo:
    p = Path(path)
    data = p.read_bytes()
    return detect_bytes(data)

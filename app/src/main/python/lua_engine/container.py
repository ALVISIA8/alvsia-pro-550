from __future__ import annotations

from dataclasses import dataclass
import zlib

LUA_MAGIC = b"\x1bLua"
LJ_MAGIC = b"\x1bLJ"


@dataclass(frozen=True)
class ContainerInfo:
    wrapped: bool
    format: str
    chunks: int
    output_size: int
    notes: tuple[str, ...] = ()


def _raw_deflate_at(data: bytes, start: int, max_output: int):
    """Decode one raw-DEFLATE stream after a 0x78da framing marker.

    The PUBG-style sample supplied with ALVISIA has a 78da marker, a raw
    DEFLATE stream, then a small CLMM/padding separator. The 78da bytes can
    also occur inside a stream, so parsing must follow DEFLATE EOF rather
    than splitting on every 78da occurrence.
    """
    dec = zlib.decompressobj(-15)
    out = dec.decompress(data[start:])
    if len(out) > max_output:
        raise ValueError("compressed Lua container exceeds output limit")
    out += dec.flush()
    if not dec.eof:
        raise ValueError("truncated raw-DEFLATE Lua container stream")
    consumed = len(data[start:]) - len(dec.unused_data)
    return out, start + consumed


def unwrap_lua_container(data: bytes, max_output: int = 256 * 1024 * 1024):
    """Return (payload, ContainerInfo).

    Supports normal zlib data and the chunked 0x78da/raw-DEFLATE container
    observed in the supplied CharacterBase.lua. If data is not a container,
    the original bytes are returned unchanged.
    """
    if not data.startswith(b"\x78\xda"):
        return data, ContainerInfo(False, "none", 0, len(data), ())

    # First try a normal zlib stream. This handles ordinary .zlib files.
    try:
        payload = zlib.decompress(data)
        if payload and (payload.startswith(LUA_MAGIC) or payload.startswith(LJ_MAGIC)):
            if len(payload) > max_output:
                raise ValueError("decompressed Lua payload exceeds output limit")
            return payload, ContainerInfo(True, "zlib", 1, len(payload),
                                          ("standard zlib container",))
    except zlib.error:
        pass

    chunks = []
    pos = 0
    total = 0
    first = True
    while True:
        marker = data.find(b"\x78\xda", pos)
        if marker < 0:
            break
        try:
            chunk, end = _raw_deflate_at(data, marker + 2, max_output - total)
        except (zlib.error, ValueError):
            if first:
                raise ValueError("78da container found but raw-DEFLATE payload is invalid")
            # A trailing accidental marker is ignored; a real next chunk must
            # successfully decode, otherwise the already recovered payload is
            # still more useful than discarding it.
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_output:
            raise ValueError("decompressed Lua payload exceeds output limit")
        pos = end
        first = False

    payload = b"".join(chunks)
    if not payload:
        raise ValueError("78da container contains no valid DEFLATE payload")

    notes = ["chunked raw-DEFLATE container"]
    if b"CLMM" in data[: min(len(data), 4096 * 1024)]:
        notes.append("CLMM/padding separators detected")
    if payload.startswith(LUA_MAGIC):
        notes.append("Lua bytecode recovered from container")
    elif payload.startswith(LJ_MAGIC):
        notes.append("LuaJIT bytecode recovered from container")
    else:
        notes.append("payload recovered but Lua magic is absent")
    return payload, ContainerInfo(True, "chunked-raw-deflate", len(chunks), len(payload), tuple(notes))

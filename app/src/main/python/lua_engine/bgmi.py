"""BGMI/PUBG Lua 5.3 chunk normalization.

The game format uses custom opcode numbers, 4-byte string sizes and delta
line information. Decrypting it means converting that layout to a standard
Lua 5.3 chunk before running a source decompiler. An empty key performs a
structure-only conversion and preserves encrypted string bytes.
"""
from __future__ import annotations
from pathlib import Path
import struct

BGMI_STD = {
    0:13,1:14,2:15,3:16,4:17,5:18,14:27,16:29,17:0,18:1,
    20:3,21:4,22:5,23:6,24:7,25:8,26:9,27:10,28:11,29:12,
    30:30,31:31,32:32,33:33,34:34,36:36,37:37,38:38,39:39,
    40:40,41:41,42:42,43:43,44:44,45:45,
}
STD_BGMI = {v:k for k,v in BGMI_STD.items()}
STD_FMT = [0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
           0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,2,2,0,2,0,1,0,3]


class _R:
    def __init__(self, data):
        self.d=data
        self.p=0
    def need(self,n):
        if n < 0 or self.p+n > len(self.d):
            raise ValueError("truncated Lua chunk")
    def byte(self):
        self.need(1); v=self.d[self.p]; self.p+=1; return v
    def u32(self):
        self.need(4); v=struct.unpack_from("<I",self.d,self.p)[0]; self.p+=4; return v
    def u64(self):
        self.need(8); v=struct.unpack_from("<Q",self.d,self.p)[0]; self.p+=8; return v
    def i32(self):
        self.need(4); v=struct.unpack_from("<i",self.d,self.p)[0]; self.p+=4; return v
    def raw(self,n):
        self.need(n); v=self.d[self.p:self.p+n]; self.p+=n; return v


class _W:
    def __init__(self):
        self.b=bytearray()
    def byte(self,v):
        self.b.append(v & 255)
    def u32(self,v):
        self.b.extend(struct.pack("<I",v & 0xffffffff))
    def u64(self,v):
        self.b.extend(struct.pack("<Q",v & 0xffffffffffffffff))
    def i32(self,v):
        self.b.extend(struct.pack("<i",int(v)))
    def raw(self,data):
        self.b.extend(data)


def is_bgmi_lua(data: bytes) -> bool:
    """Identify the 32-bit-size_t Lua 5.3 ABI used by the BGMI transform."""
    return (
        len(data) >= 33
        and data[:5] == b"\x1bLua\x53"
        and data[12:17] == b"\x04\x04\x04\x08\x08"
    )


def transform_bgmi_lua(data: bytes, key: bytes = b"", decrypt=True) -> bytes:
    """Convert BGMI Lua 5.3 to standard Lua 5.3 (or reverse with decrypt=False).

    With decrypt=True and no XOR key, the structure/opcodes are still
    normalized but encrypted string bytes are preserved verbatim. This is
    useful for a diagnostic decompile and is never represented as full string
    recovery.
    """
    if len(data) < 34 or not data.startswith(b"\x1bLua\x53"):
        raise ValueError("not Lua 5.3 bytecode")
    key = bytes(key or b"")
    if not decrypt and not key:
        raise ValueError("XOR key is required to encode BGMI strings")

    input_sizet = data[13]
    r, w = _R(data), _W()
    hdr = bytearray(data[:33])
    if decrypt:
        hdr[13] = 8
    elif hdr[12:16] == b"\x04\x08\x04\x08":
        hdr[12:16] = b"\x04\x04\x04\x08"
    w.raw(hdr)
    r.p = 33
    w.byte(r.byte())  # main proto upvalue count

    def sread():
        size = r.byte()
        if size == 0:
            return None
        if size == 0xFF:
            # BGMI uses uint32 lengths; standard Lua uses sizeof(size_t).
            size = r.u32() if decrypt else (r.u64() if input_sizet == 8 else r.u32())
        if size < 1:
            raise ValueError("invalid Lua string length")
        raw = r.raw(size - 1)
        if decrypt and key:
            raw = bytes(value ^ key[i % len(key)] for i, value in enumerate(raw))
        # Bytes preserve opaque/XOR-encrypted constants without lossy UTF-8 replacement.
        return raw

    def swrite(value, encrypt):
        if value is None:
            w.byte(0)
            return
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if encrypt and key:
            raw = bytes(value ^ key[i % len(key)] for i, value in enumerate(raw))
        size = len(raw) + 1
        if size < 0xFF:
            w.byte(size)
        else:
            w.byte(0xFF)
            if decrypt:
                w.u64(size)
            else:
                w.u32(size)
        w.raw(raw)

    def convert():
        swrite(sread(), not decrypt)
        w.i32(r.i32())  # line defined
        last_line = r.i32()
        w.i32(last_line)
        w.byte(r.byte()); w.byte(r.byte()); w.byte(r.byte())
        code_count = r.u32()
        if code_count > 5_000_000:
            raise ValueError("unreasonable Lua instruction count")
        w.u32(code_count)
        for _ in range(code_count):
            raw = r.u32()
            op = raw & 0x3F
            a = (raw >> 6) & 0xFF
            b = (raw >> 23) & 0x1FF
            c = (raw >> 14) & 0x1FF
            bx = (raw >> 14) & 0x3FFFF
            ax = (raw >> 6) & 0x3FFFFFF
            sbx = bx - 131071
            if decrypt:
                if op not in BGMI_STD:
                    raise ValueError(f"unsupported BGMI opcode {op} at instruction {_}")
                sop = BGMI_STD[op]
                if not 0 <= sop < len(STD_FMT):
                    raise ValueError(f"invalid normalized opcode {sop} at instruction {_}")
                fmt = STD_FMT[sop]
            else:
                if op not in STD_FMT or op not in STD_BGMI:
                    raise ValueError(f"unsupported standard opcode {op} at instruction {_}")
                sop = STD_BGMI[op]
                fmt = STD_FMT[op]
            if fmt == 0:
                encoded = (sop & 0x3F) | (a << 6) | (c << 14) | (b << 23)
            elif fmt == 1:
                encoded = (sop & 0x3F) | (a << 6) | (bx << 14)
            elif fmt == 2:
                encoded = (sop & 0x3F) | (a << 6) | ((sbx + 131071) << 14)
            else:
                encoded = (sop & 0x3F) | (ax << 6)
            w.u32(encoded)

        constant_count = r.u32()
        if constant_count > 5_000_000:
            raise ValueError("unreasonable Lua constant count")
        w.u32(constant_count)
        for _ in range(constant_count):
            tag = r.byte(); w.byte(tag)
            if tag == 1:
                w.byte(r.byte())
            elif tag in (3, 19):
                w.raw(r.raw(8))
            elif tag in (4, 20):
                swrite(sread(), not decrypt)

        upvalue_count = r.u32(); w.u32(upvalue_count)
        if upvalue_count > 500_000:
            raise ValueError("unreasonable Lua upvalue count")
        for _ in range(upvalue_count):
            w.byte(r.byte()); w.byte(r.byte())

        child_count = r.u32(); w.u32(child_count)
        if child_count > 500_000:
            raise ValueError("unreasonable Lua proto count")
        for _ in range(child_count):
            convert()

        line_count = r.u32()
        if line_count > 5_000_000:
            raise ValueError("unreasonable Lua lineinfo count")
        if decrypt:
            # BGMI delta bytes -> standard Lua int32 line numbers.
            current = last_line
            lines = []
            for _ in range(line_count):
                delta = r.byte()
                current += delta if delta <= 127 else delta - 256
                lines.append(current)
            w.u32(len(lines))
            for line in lines:
                w.i32(line)
            # BGMI stores absolute-line entries here; standard Lua 5.3 does not.
            abs_count = r.u32()
            if abs_count > 5_000_000:
                raise ValueError("unreasonable BGMI absolute lineinfo count")
            r.raw(abs_count * 8)
        else:
            # Standard Lua int32 line numbers -> BGMI signed byte deltas.
            lines = [r.i32() for _ in range(line_count)]
            w.u32(len(lines))
            current = last_line
            for line in lines:
                delta = line - current
                current = line
                if delta < -128 or delta > 127:
                    raise ValueError("line delta is outside BGMI signed-byte range")
                w.byte(delta & 255)
            w.u32(0)  # no absolute-line entries in generated BGMI data

        locvar_count = r.u32(); w.u32(locvar_count)
        if locvar_count > 500_000:
            raise ValueError("unreasonable Lua local-variable count")
        for _ in range(locvar_count):
            swrite(sread(), not decrypt)
            w.i32(r.i32()); w.i32(r.i32())

        uv_name_count = r.u32(); w.u32(uv_name_count)
        if uv_name_count > 500_000:
            raise ValueError("unreasonable Lua upvalue-name count")
        for _ in range(uv_name_count):
            swrite(sread(), not decrypt)

    convert()
    if r.p > len(data):
        raise ValueError("Lua transform parser overrun")
    return bytes(w.b)

"""
lua_engine/luajit_decompiler.py
ALVSIA PRO — LuaJIT 2.0/2.1 bytecode disassembler.

LuaJIT bytecode format:
  Header: \x1bLJ \x02 (LuaJIT 2.0) or \x1bLJ \x02 (same magic, different flag byte)
  Flags: 1 byte (bit0=BE, bit1=strip, bit2=ffi)
  Then length-prefixed proto list (GCproto chain).

This is a disassembler (shows instructions + constants), not a full decompiler.
For a full decompiler, LuaJIT source + ljd/luajit-decompiler are needed.

Public API:
    disassemble_luajit(src_path, dst_path) -> dict
    detect_luajit(data: bytes) -> bool
"""
from __future__ import annotations
import struct, re
from pathlib import Path
from typing import List, Optional, Tuple, Any

LUAJIT_MAGIC = b"\x1bLJ"

# LuaJIT 2.x opcodes (simplified subset — enough for readable disassembly)
LJ_OPS = [
    # Comparison ops (00-15)
    "ISLT","ISGE","ISLE","ISGT","ISEQV","ISNEV","ISEQS","ISNES",
    "ISEQN","ISNEN","ISEQP","ISNEP",
    # Unary test and copy ops
    "ISTC","ISFC","IST","ISF","ISTYPE","ISNUM",
    # Unary ops
    "MOV","NOT","UNM","LEN","ADDVN","SUBVN","MULVN","DIVVN","MODVN",
    "ADDNV","SUBNV","MULNV","DIVNV","MODNV","ADDVV","SUBVV","MULVV",
    "DIVVV","MODVV","POW","CAT",
    # Constant ops
    "KSTR","KCDATA","KSHORT","KNUM","KPRI","KNIL",
    # Upvalue and function ops
    "UGET","USETV","USETS","USETN","USETP","UCLO","FNEW",
    # Table ops
    "TNEW","TDUP","GGET","GSET","TGETV","TGETS","TGETB","TGETR",
    "TSETV","TSETS","TSETB","TSETM","TSETR",
    # Calls and vararg handling
    "CALLM","CALL","CALLMT","CALLT","ITERC","ITERN","VARG","ISNEXT",
    # Returns
    "RETM","RET","RET0","RET1",
    # Loops and branches (must be in order)
    "FORI","JFORI","FORL","IFORL","JFORL","ITERL","IITERL","JITERL",
    "LOOP","ILOOP","JLOOP","JMP",
    # Function headers
    "FUNCF","IFUNCF","JFUNCF","FUNCV","IFUNCV","JFUNCV","FUNCC","FUNCCW",
]


def detect_luajit(data: bytes) -> bool:
    """Return True if bytes start with LuaJIT 2.x magic."""
    return len(data) >= 4 and data[:3] == LUAJIT_MAGIC and data[3] in (0x01, 0x02)


class _LJReader:
    """Simple forward-reading buffer for LuaJIT protos."""
    def __init__(self, data: bytes):
        self._d = data; self._p = 0

    def remaining(self) -> int:
        return len(self._d) - self._p

    def read(self, n: int) -> bytes:
        if self._p + n > len(self._d):
            raise EOFError(f"need {n} at {self._p:#x}")
        v = self._d[self._p:self._p+n]; self._p += n; return v

    def u8(self) -> int:
        return self.read(1)[0]

    def u16le(self) -> int:
        return struct.unpack_from("<H", self.read(2))[0]

    def u32le(self) -> int:
        return struct.unpack_from("<I", self.read(4))[0]

    def uleb128(self) -> int:
        result = shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7f) << shift
            if not (b & 0x80): break
            shift += 7
        return result

    def uleb128_33(self) -> Tuple[int, int]:
        """ULEB128-33: first bit is sign, rest is 32-bit value."""
        v = self.uleb128()
        return (v >> 1), (v & 1)  # value, is_negative


def _read_lj_string(r: _LJReader) -> Optional[str]:
    """Read LuaJIT length-prefixed string (uleb128 len then bytes)."""
    ln = r.uleb128()
    if ln == 0:
        return None
    data = r.read(ln - 1)  # length includes null terminator
    return data.decode("utf-8", errors="replace")


def _disassemble_proto(r: _LJReader, out: List[str], depth: int = 0) -> bool:
    """Read one GCproto and append disassembly lines. Returns True on success."""
    indent = "  " * depth
    try:
        proto_len = r.uleb128()
        if proto_len == 0:
            return False  # end of proto list

        start_pos = r._p
        flags       = r.u8()
        num_params  = r.u8()
        frame_size  = r.u8()
        num_uv      = r.u8()
        num_kgc     = r.uleb128()
        num_kn      = r.uleb128()
        num_bc      = r.uleb128()

        # optional debug info
        if not (flags & 0x02):   # strip flag not set → debug info present
            debug_size = r.uleb128()
            if debug_size:
                first_line  = r.uleb128()
                num_lines   = r.uleb128()
        else:
            debug_size = first_line = num_lines = 0

        out.append(f"{indent}-- proto: params={num_params} frame={frame_size} uv={num_uv} bc={num_bc}")

        # bytecode instructions (each 4 bytes: OP A B/C/D)
        for i in range(num_bc):
            raw = r.read(4)
            op_id = raw[0]
            a  = raw[1]
            cd = struct.unpack_from("<H", raw, 2)[0]
            b  = cd >> 8
            c  = cd & 0xff
            d  = cd
            op_name = LJ_OPS[op_id] if op_id < len(LJ_OPS) else f"OP_{op_id:#04x}"
            out.append(f"{indent}  [{i:5d}] {op_name:<12} A={a} B={b} C={c} D={d}")

        # GC constants
        for i in range(num_kgc):
            ktype = r.uleb128()
            if ktype >= 5:   # KGCO_STR
                s = _read_lj_string(r)
                out.append(f"{indent}  .kgc[{i}] str={repr(s)}")
            elif ktype == 0:  # KGCO_CHILD
                out.append(f"{indent}  .kgc[{i}] child_proto")
                # child proto is embedded — parse it recursively
                _disassemble_proto(r, out, depth + 1)
            elif ktype == 1:  # KGCO_TAB
                narray = r.uleb128(); nhash = r.uleb128()
                out.append(f"{indent}  .kgc[{i}] table narray={narray} nhash={nhash}")
                r.read(narray * 4)  # skip array values (approximate)
            elif ktype in (2, 3, 4):  # INT64, UINT64, COMPLEX
                r.read(8)
                out.append(f"{indent}  .kgc[{i}] type={ktype}")

        # number constants (ULEB128 encoded)
        for i in range(num_kn):
            v, is_int = r.uleb128_33()
            if is_int:
                out.append(f"{indent}  .kn[{i}] int={v}")
            else:
                # float: next uleb128 is the hi word
                hi = r.uleb128()
                fval = struct.unpack("<d", struct.pack("<II", v, hi))[0]
                out.append(f"{indent}  .kn[{i}] float={fval}")

        # skip debug info if present (variable size — just advance to end)
        consumed = r._p - start_pos
        remaining = proto_len - consumed
        if remaining > 0:
            r.read(remaining)
        elif remaining < 0:
            pass  # over-read — can't recover; parser is approximate

        return True
    except (EOFError, struct.error) as e:
        out.append(f"{indent}-- parse error: {e}")
        return False


def disassemble_luajit(src_path: "Path | str", dst_path: "Path | str") -> dict:
    """
    Disassemble a LuaJIT 2.x bytecode file to a human-readable text format.
    Returns {"ok": True, "out": str, "lines": int} or {"ok": False, "error": str}.
    """
    src_path = Path(src_path); dst_path = Path(dst_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    data = src_path.read_bytes()
    if not detect_luajit(data):
        # check if it's compressed (common for LuaJIT files in games)
        if len(data) > 2 and data[:2] == b"\x78\x9c":
            import zlib
            try:
                data = zlib.decompress(data)
            except Exception:
                pass
        if not detect_luajit(data):
            return {"ok": False, "error": f"not LuaJIT magic: {data[:4].hex()}"}

    r = _LJReader(data)
    out_lines: List[str] = []

    # header
    magic = r.read(3)        # \x1bLJ
    version = r.u8()         # 0x01 or 0x02
    flags = r.uleb128()
    is_be    = bool(flags & 1)
    is_strip = bool(flags & 2)
    has_ffi  = bool(flags & 4)

    out_lines.append(f"-- LuaJIT {version:#x} bytecode disassembly")
    out_lines.append(f"-- flags: BE={is_be} strip={is_strip} ffi={has_ffi}")
    out_lines.append(f"-- source: {src_path.name}")
    out_lines.append("")

    # chunk name
    chunk_name = _read_lj_string(r)
    out_lines.append(f"-- chunk: {chunk_name!r}")
    out_lines.append("")

    # proto chain
    proto_count = 0
    while r.remaining() > 0:
        out_lines.append(f"-- === proto #{proto_count} ===")
        if not _disassemble_proto(r, out_lines, 0):
            break
        proto_count += 1
        if proto_count > 2000:
            out_lines.append("-- [truncated: too many protos]")
            break

    dst_path.write_text("\n".join(out_lines), encoding="utf-8")
    return {"ok": True, "out": str(dst_path), "lines": len(out_lines),
            "protos": proto_count, "version": f"LuaJIT {version:#x}"}

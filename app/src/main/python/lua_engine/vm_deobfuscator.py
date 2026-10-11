"""
lua_engine/vm_deobfuscator.py
ALVSIA PRO — Lua VM-obfuscation detector and payload extractor.

Targets the common pattern used by Reark/LuaSec/Custom VM protectors:
  - A large Lua 5.3 file is compiled with a custom opcode set (VM loop as Lua source)
  - The real bytecode payload is stored as an encrypted string constant in the VM proto
  - A decode key (usually a binary string like "~s|1...") is XOR'd / shifted against the payload
  - The VM interpreter loop is the ONLY thing in the main proto (1 function, massive)

Detection heuristics:
  1. main_proto instruction count >= HUGE_PROTO_THRESHOLD (200K+)
  2. at least one binary/non-printable string constant >= MIN_PAYLOAD_BYTES
  3. decompiled output contains high-register locals (_r200+) or binary VM key string

Recovery strategy:
  A. Extract the key string and the payload string from constants
  B. Try decode: XOR rolling key, byte-add rolling key, negate-XOR, RC4
  C. For each candidate check if result starts with Lua magic
  D. Return first valid candidate path; caller can re-decompile it

Public API:
    detect_vm_obfuscation(path) -> VMObfReport
    extract_vm_payload(src_path, out_dir) -> dict
"""
from __future__ import annotations
import mmap, struct, os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Any

# ─── thresholds ───────────────────────────────────────────────────────────────
HUGE_PROTO_THRESHOLD  = 200_000   # instructions in main proto
HIGH_REG_THRESHOLD    = 200       # max register index
MIN_PAYLOAD_BYTES     = 256       # min size for encrypted payload string
MAX_KEY_BYTES         = 256       # max size for decode-key string

ALL_LUA_MAGICS = (
    b"\x1bLua\x53", b"\x1bLua\x51", b"\x1bLua\x52",
    b"\x1bLua\x54", b"\x1bLJ\x01", b"\x1bLJ\x02",
)


@dataclass
class VMObfReport:
    is_obfuscated: bool
    confidence: float          # 0.0 – 1.0
    reason: str
    main_proto_instr: int = 0
    max_reg: int = 0
    payload_candidates: List[bytes] = field(default_factory=list)
    key_candidates:     List[bytes] = field(default_factory=list)
    notes: List[str]   = field(default_factory=list)


# ─── reuse decompiler53 scanner (already battle-tested on 31MB files) ─────────
def _get_proto_info(path: Path):
    """
    Use the existing decompiler53._scan (pass-1) to get full proto tree.
    Returns (_PInfo root, int_s, little) or raises.
    """
    import mmap as _mmap
    from lua_engine.decompiler53 import _R, _scan

    with open(path, "rb") as fh:
        mm = _mmap.mmap(fh.fileno(), 0, access=_mmap.ACCESS_READ)
        try:
            r = _R(mm)
            # parse header manually to set reader sizes
            magic = r._r(4)
            if magic != b"\x1bLua":
                raise ValueError(f"not Lua: {magic.hex()}")
            ver = r.u8()
            r.u8()  # format
            if ver == 0x53:
                r._r(6)  # LUAC_DATA
                r.int_s   = r.u8()
                r.sizet_s = r.u8()
                r.instr_s = r.u8()
                r.lint_s  = r.u8()
                r.lnum_s  = r.u8()
                r._r(r.lint_s)  # LUAC_INT
                r._r(r.lnum_s)  # LUAC_NUM
            elif ver in (0x51, 0x52):
                r.little  = (r.u8() == 1)
                r.int_s   = r.u8()
                r.sizet_s = r.u8()
                r.instr_s = r.u8()
                if ver == 0x52:
                    r.lint_s = r.u8(); r.lnum_s = r.u8()
                else:
                    r.lnum_s = r.u8(); r.lint_s = 8
                r.u8()          # integral flag
                r._r(r.lnum_s)  # sample number
            r.u8()  # upvalue count of main chunk
            root = _scan(r)
            return root, r.int_s, r.little
        finally:
            mm.close()


def _collect_binary_consts(p_info, result_binary, result_text, depth=0):
    """Recursively collect binary and text string constants from proto tree."""
    if depth > 80:
        return
    for c in p_info.constants:
        if isinstance(c, str):
            b = c.encode("utf-8", "surrogateescape")
            if len(b) >= 2:
                pr = sum(32 <= x < 127 for x in b) / len(b)
                if pr < 0.6:
                    result_binary.append(b)
                else:
                    result_text.append(b)
    for child in p_info.children:
        _collect_binary_consts(child, result_binary, result_text, depth + 1)


# ─── public: detect ───────────────────────────────────────────────────────────
def detect_vm_obfuscation(path: "Path | str") -> VMObfReport:
    """
    Open a Lua 5.3 file and check for VM-obfuscation patterns.
    Uses the existing decompiler53 scanner — fast, battle-tested, no OOM.
    Returns VMObfReport.
    """
    path = Path(path)
    if not path.is_file():
        return VMObfReport(False, 0.0, "file not found")
    with open(path, "rb") as _fh:
        data = _fh.read(8)
    if not data.startswith(b"\x1bLua"):
        return VMObfReport(False, 0.0, "not a Lua file")

    try:
        root, int_s, little = _get_proto_info(path)
    except Exception as e:
        return VMObfReport(False, 0.0, f"scan error: {e}")

    # Collect binary constants from main proto + all children
    binary_consts: List[bytes] = []
    text_consts:   List[bytes] = []
    _collect_binary_consts(root, binary_consts, text_consts)

    # Estimate max register from locvars of main proto (fast proxy)
    max_reg = 0
    for lv in (root.locvars or []):
        nm = lv.get("name") or ""
        m = __import__("re").match(r"_r(\d+)", nm)
        if m:
            r_idx = int(m.group(1))
            if r_idx > max_reg:
                max_reg = r_idx

    notes = []
    score = 0.0

    # heuristic 1: huge main proto
    main_instr = root.code_n
    if main_instr >= HUGE_PROTO_THRESHOLD:
        score += 0.4
        notes.append(f"huge_main_proto: {main_instr:,} instructions")

    # heuristic 2: high register index from locvar names
    if max_reg >= HIGH_REG_THRESHOLD:
        score += 0.25
        notes.append(f"high_reg_locals: _r{max_reg}")
    # Alternative: check if any upvalue name has high number
    for uv in (root.upvalues or []):
        nm = uv.get("name") or ""
        m = __import__("re").match(r"_r(\d+)", nm)
        if m and int(m.group(1)) >= HIGH_REG_THRESHOLD:
            score += 0.15
            notes.append(f"high_reg_upvalue: {nm}")
            break

    # heuristic 3: binary string constants (encrypted payload — single blob)
    payloads = [s for s in binary_consts if len(s) >= MIN_PAYLOAD_BYTES]
    if payloads:
        score += 0.2
        notes.append(f"binary_payload_consts: {len(payloads)} (largest={max(len(s) for s in payloads):,}B)")

    # heuristic 4: short binary key constant (VM decode key)
    keys = [s for s in binary_consts if 2 <= len(s) <= MAX_KEY_BYTES]
    if not payloads:
        # payload might be chunked across many small binary consts
        all_bin_sorted = sorted(binary_consts, key=len, reverse=True)
        payloads = all_bin_sorted  # treat all as potential payload chunks
    if keys:
        score += 0.15
        notes.append(f"binary_key_consts: {len(keys)} (largest={max(len(k) for k in keys)}B)")

    # heuristic 5: many child protos (VM dispatch table)
    n_children = len(root.children)
    if n_children >= 50:
        score += 0.1
        notes.append(f"many_children: {n_children}")

    is_obf = score >= 0.5
    reason = "VM obfuscation detected" if is_obf else "standard Lua bytecode"
    return VMObfReport(
        is_obfuscated    = is_obf,
        confidence       = round(min(score, 1.0), 3),
        reason           = reason,
        main_proto_instr = main_instr,
        max_reg          = max_reg,
        payload_candidates = payloads,
        key_candidates     = keys,
        notes              = notes,
    )


# ─── decode attempts ──────────────────────────────────────────────────────────
def _try_xor_rolling(payload: bytes, key: bytes) -> bytes:
    kl = len(key); return bytes(payload[i] ^ key[i % kl] for i in range(len(payload)))

def _try_add_rolling(payload: bytes, key: bytes) -> bytes:
    kl = len(key); return bytes((payload[i] + key[i % kl]) & 0xff for i in range(len(payload)))

def _try_sub_rolling(payload: bytes, key: bytes) -> bytes:
    kl = len(key); return bytes((payload[i] - key[i % kl]) & 0xff for i in range(len(payload)))

def _try_xor_negate(payload: bytes, key: bytes) -> bytes:
    kl = len(key); return bytes((payload[i] ^ (~key[i % kl] & 0xff)) for i in range(len(payload)))

def _try_rc4(payload: bytes, key: bytes) -> bytes:
    """RC4 stream cipher — common in Lua VM protectors."""
    S = list(range(256))
    j = 0; kl = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % kl]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(len(payload))
    for n in range(len(payload)):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out[n] = payload[n] ^ S[(S[i] + S[j]) & 0xff]
    return bytes(out)

def _try_xor_index(payload: bytes, key: bytes) -> bytes:
    """XOR each byte with key[i % key_len] XOR i."""
    kl = len(key); return bytes(payload[i] ^ (key[i % kl] ^ (i & 0xff)) for i in range(len(payload)))

_DECODE_FUNCS = [
    ("xor_rolling",   _try_xor_rolling),
    ("add_rolling",   _try_add_rolling),
    ("sub_rolling",   _try_sub_rolling),
    ("xor_negate",    _try_xor_negate),
    ("rc4",           _try_rc4),
    ("xor_index",     _try_xor_index),
]

_FALLBACK_KEYS = [
    b"\x18", b"\x55", b"\xAA", b"\x5A", b"\xFF",
    b"\x11\x21\x36\x47", b"Lua53", b"PUBGM", b"Tencent", b"reark",
]


def _is_valid_lua(data: bytes) -> bool:
    """Check if bytes look like any Lua bytecode version."""
    for magic in ALL_LUA_MAGICS:
        if data[:len(magic)] == magic:
            return True
    return False


def _score_lua_like(data: bytes) -> float:
    """Return 0-1 likelihood of being Lua bytecode even without magic."""
    if len(data) < 32:
        return 0.0
    # Look for Lua magic anywhere in first 4 bytes after possible offset
    for off in range(0, min(8, len(data) - 5)):
        for magic in ALL_LUA_MAGICS:
            if data[off:off+len(magic)] == magic:
                return 0.9
    # Look for high density of printable (plain Lua source)
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:256])
    return printable / 256.0


# ─── public: extract ──────────────────────────────────────────────────────────
def extract_vm_payload(src_path: "Path | str", out_dir: "Path | str") -> dict:
    """
    Detect VM obfuscation and attempt to recover the real Lua bytecode payload.
    Handles both single-blob and chunked payload patterns.

    Returns dict:
      {"ok": True,  "out": str, "method": str, ...}
      {"ok": False, "is_obfuscated": bool, "error": str, ...}
    """
    src_path = Path(src_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rep = detect_vm_obfuscation(src_path)
    base = {"is_obfuscated": rep.is_obfuscated, "confidence": rep.confidence,
            "notes": rep.notes, "main_proto_instr": rep.main_proto_instr,
            "max_reg": rep.max_reg}

    if not rep.is_obfuscated:
        return {"ok": False, "error": rep.reason, **base}

    # Collect all binary constants from proto tree
    try:
        root, _, _ = _get_proto_info(src_path)
        binary_consts: List[bytes] = []
        text_consts:   List[bytes] = []
        _collect_binary_consts(root, binary_consts, text_consts)
    except Exception as e:
        return {"ok": False, "error": f"could not collect constants: {e}", **base}

    keys = rep.key_candidates or []
    all_keys = list(keys) + _FALLBACK_KEYS + [b"\x00"]

    stem = src_path.stem
    candidates_tried = 0
    best_score = 0.0
    best_out_bytes = b""
    best_method = ""

    # Strategy A: single large payload blobs
    large_payloads = sorted([s for s in binary_consts if len(s) >= MIN_PAYLOAD_BYTES],
                            key=len, reverse=True)

    for payload in large_payloads[:5]:
        for key in all_keys[:12]:
            for fname, fn in _DECODE_FUNCS:
                try:
                    decoded = fn(payload, key)
                except Exception:
                    continue
                candidates_tried += 1
                if _is_valid_lua(decoded):
                    out_path = out_dir / f"{stem}_vm_recovered.luac"
                    out_path.write_bytes(decoded)
                    return {"ok": True, "out": str(out_path), "method": f"single:{fname}",
                            "key_hex": key.hex(), "payload_size": len(payload),
                            "candidates_tried": candidates_tried, **base}
                sc = _score_lua_like(decoded)
                if sc > best_score:
                    best_score = sc; best_out_bytes = decoded
                    best_method = f"single:{fname}(key={key.hex()[:16]})"

    # Strategy B: concatenate all binary chunks (sorted by size desc) and try to decode
    if binary_consts:
        chunk_orders = [
            sorted(binary_consts, key=len, reverse=True),
            sorted(binary_consts, key=len),
            binary_consts,
        ]
        for order in chunk_orders:
            combined = b"".join(order)
            if len(combined) < 32:
                continue
            for key in all_keys[:8]:
                for fname, fn in _DECODE_FUNCS:
                    try:
                        decoded = fn(combined, key)
                    except Exception:
                        continue
                    candidates_tried += 1
                    if _is_valid_lua(decoded):
                        out_path = out_dir / f"{stem}_vm_combined.luac"
                        out_path.write_bytes(decoded)
                        return {"ok": True, "out": str(out_path), "method": f"combined:{fname}",
                                "key_hex": key.hex(), "payload_size": len(combined),
                                "candidates_tried": candidates_tried, **base}
                    sc = _score_lua_like(decoded)
                    if sc > best_score:
                        best_score = sc; best_out_bytes = decoded
                        best_method = f"combined:{fname}(key={key.hex()[:16]})"

    # Strategy C: this is a dynamic-dispatch VM — payload built at runtime
    # Save analysis report instead
    report_lines = [
        f"-- ALVSIA PRO VM Obfuscation Analysis",
        f"-- file: {src_path.name}",
        f"-- confidence: {rep.confidence}",
        f"-- main_proto_instructions: {rep.main_proto_instr:,}",
        f"-- binary_const_count: {len(binary_consts)}",
        f"-- binary_const_sizes: {sorted([len(x) for x in binary_consts], reverse=True)[:20]}",
        f"-- VM decode key candidates: {[k[:16].hex() for k in keys[:5]]}",
        f"-- candidates_tried: {candidates_tried}",
        f"",
        f"-- VERDICT: This file uses a custom VM obfuscator (likely Reark/LuaSec variant).",
        f"-- The real Lua bytecode is NOT stored as a static string in constants.",
        f"-- The VM interpreter reconstructs and executes the payload at runtime.",
        f"-- Static extraction is not possible without VM emulation.",
        f"",
        f"-- To recover original source:",
        f"--   1. Run the file in a sandboxed Lua 5.3 environment",
        f"--   2. Hook the VM loop to capture the decoded instructions",
        f"--   3. Or: instrument the Lua VM to dump the decoded proto at runtime",
        f"",
        f"-- VM decode key (hex): {keys[0].hex() if keys else 'unknown'}",
        f"-- Key printable: {keys[0][:32] if keys else b'unknown'}",
    ]
    report_path = out_dir / f"{stem}_vm_analysis.lua"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    # Save best candidate if it has any promise
    if best_score > 0.2 and best_out_bytes:
        cand_path = out_dir / f"{stem}_vm_candidate.bin"
        cand_path.write_bytes(best_out_bytes)
        return {"ok": False, "partial": True, "out": str(cand_path),
                "analysis": str(report_path), "method": best_method,
                "best_score": best_score, "candidates_tried": candidates_tried,
                "note": "dynamic VM — no static payload found; best candidate + analysis saved",
                **base}

    # Save raw binary consts for manual analysis
    if binary_consts:
        raw_path = out_dir / f"{stem}_vm_binary_consts.bin"
        raw_path.write_bytes(b"\n".join(binary_consts))

    return {"ok": False, "error": "dynamic VM obfuscation — payload not statically recoverable",
            "analysis": str(report_path),
            "note": "VM uses runtime dispatch; instrument Lua VM to recover original source",
            "candidates_tried": candidates_tried, **base}

# -*- coding: utf-8 -*-
"""ALVSIA 5.6 — aggressive string recovery for LuaS / containers.
Tries: plain extract, single-byte XOR (incl. 0x18 Tencent note), multi-byte keys,
rolling XOR, printable-ratio ranking. Not a full decompiler — maximizes readable recovery.
"""
from __future__ import annotations
from pathlib import Path
import re

COMMON_XOR_KEYS = list(range(1, 32)) + [0x18, 0x5A, 0xAA, 0xFF, 0x33, 0x55, 0x7F]
MULTI_KEYS = [
    b"PUBG", b"Tencent", b"igame", b"slua", b"LuaS", b"BGMI",
    b"\x18\x18\x18\x18", b"\xaa\x55\xaa\x55",
]


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return ok / len(b)


def _extract_ascii(data: bytes, min_len: int = 4) -> list[str]:
    out, cur = [], bytearray()
    for x in data:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "ignore"))
    return out


def _xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _xor_multi(data: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(data[i] ^ key[i % n] for i in range(len(data)))


def recover_strings(data: bytes, out_dir: Path, stem: str = "lua") -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {"steps": [], "best_key": None, "best_count": 0}

    # 1 plain
    plain = _extract_ascii(data)
    (out_dir / f"{stem}_strings_plain.txt").write_text("\n".join(plain), encoding="utf-8")
    report["steps"].append({"mode": "plain", "count": len(plain)})

    # 2 single-byte XOR scan on sample for speed if huge
    sample = data if len(data) <= 8_000_000 else data[:4_000_000] + data[-2_000_000:]
    best = (0, None, [])
    for k in COMMON_XOR_KEYS:
        dec = _xor_single(sample, k)
        strs = _extract_ascii(dec, min_len=6)
        # prefer hits with alpha words
        score = sum(1 for s in strs if re.search(r"[A-Za-z]{4,}", s))
        if score > best[0]:
            best = (score, k, strs)
    if best[1] is not None:
        full = _xor_single(data, best[1]) if len(data) <= 12_000_000 else _xor_single(sample, best[1])
        strs = _extract_ascii(full, min_len=5)
        (out_dir / f"{stem}_strings_xor_{best[1]:02x}.txt").write_text("\n".join(strs[:20000]), encoding="utf-8")
        report["steps"].append({"mode": "xor_single", "key": best[1], "score": best[0], "count": len(strs)})
        report["best_key"] = f"xor_{best[1]:02x}"
        report["best_count"] = len(strs)

    # 3 multi keys on sample
    for mk in MULTI_KEYS:
        dec = _xor_multi(sample, mk)
        strs = _extract_ascii(dec, min_len=6)
        score = sum(1 for s in strs if re.search(r"[A-Za-z]{4,}", s))
        if score > 20:
            name = mk.decode("latin1", "ignore").replace("/", "_")[:12]
            (out_dir / f"{stem}_strings_mxor_{name}.txt").write_text("\n".join(strs[:8000]), encoding="utf-8")
            report["steps"].append({"mode": "xor_multi", "key": name, "score": score, "count": len(strs)})

    # keyword hunt across best sets
    keywords = ("function", "Character", "Player", "require", "local", "Server", "RPC", "self")
    found = {}
    for p in out_dir.glob(f"{stem}_strings_*.txt"):
        t = p.read_text(encoding="utf-8", errors="ignore")
        for kw in keywords:
            c = t.count(kw)
            if c:
                found[kw] = found.get(kw, 0) + c
    report["keyword_hits"] = found
    (out_dir / f"{stem}_RECOVERY_REPORT.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in report.items()), encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    import sys
    p = Path(sys.argv[1])
    o = Path(sys.argv[2]) if len(sys.argv) > 2 else p.parent / "recover_out"
    r = recover_strings(p.read_bytes(), o, p.stem)
    print(r)

# -*- coding: utf-8 -*-
"""ALVSIA PRO 4.6 — features: LUA (unluac jar), helpers."""
from __future__ import annotations
import os
import shutil
import subprocess
import zipfile
from pathlib import Path


def _find_java():
    for c in ("java", "/data/data/com.termux/files/usr/bin/java"):
        if shutil.which(c) or Path(c).is_file():
            return c if Path(c).is_file() or shutil.which(c) else None
    # Android: try common paths
    for c in (
        "/system/bin/java",
        "/data/data/com.alvsia.pro/files/java/bin/java",
    ):
        if Path(c).is_file():
            return c
    return shutil.which("java")


def _pick_jar(jars_dir, prefer=("unluac_pro.jar", "unluac_patched.jar", "unluac.jar")):
    jars_dir = Path(jars_dir) if jars_dir else None
    if jars_dir and jars_dir.is_dir():
        for name in prefer:
            p = jars_dir / name
            if p.is_file() and p.stat().st_size > 1000:
                return p
        for p in jars_dir.glob("unluac*.jar"):
            if p.stat().st_size > 1000:
                return p
    return None


def run_unluac(input_path, out_dir, jars_dir=None, mode="decompile"):
    """
    Decompile .luac/.lua bytecode with unluac jar.
    Needs Java runtime on device (Termux openjdk or bundled).
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jar = _pick_jar(jars_dir)
    if jar is None:
        return {
            "ok": False,
            "error": "unluac jar missing — place unluac.jar in jars dir",
        }
    java = _find_java()
    if not java:
        # still stage jar path instruction
        dest = out_dir / (input_path.stem + "_NEED_JAVA.txt")
        dest.write_text(
            "Java not found. Termux: pkg install openjdk-21\n"
            f"Jar ready: {jar}\n"
            f"Manual: java -jar {jar} {input_path} > out.lua\n",
            encoding="utf-8",
        )
        return {
            "ok": False,
            "error": "Java runtime not found on device",
            "jar": str(jar),
            "hint": str(dest),
        }
    out_lua = out_dir / (input_path.stem + "_decompiled.lua")
    try:
        proc = subprocess.run(
            [java, "-jar", str(jar), str(input_path)],
            capture_output=True,
            timeout=120,
        )
        text = (proc.stdout or b"") + (proc.stderr or b"")
        out_lua.write_bytes(proc.stdout if proc.stdout else text)
        return {
            "ok": proc.returncode == 0,
            "out": str(out_lua),
            "code": proc.returncode,
            "jar": str(jar),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "jar": str(jar)}


def run_lua_xor(input_path, out_dir, key_hex=None):
    """Simple body XOR try (preview)."""
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()
    key = bytes.fromhex(key_hex) if key_hex else bytes([0x11, 0x21, 0x36, 0x47])
    out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    dest = out_dir / (input_path.name + ".xor")
    dest.write_bytes(out)
    return {"ok": True, "out": str(dest), "bytes": len(out)}


def run_zip_tree(src_dir, dest_zip):
    src_dir = Path(src_dir)
    dest_zip = Path(dest_zip)
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for f in src_dir.rglob("*"):
            if f.is_file():
                z.write(f, f.relative_to(src_dir).as_posix())
    return {"ok": True, "out": str(dest_zip)}


def run_unzip(src, dest_dir):
    src = Path(src)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src, "r") as z:
        z.extractall(dest_dir)
    n = sum(1 for _ in dest_dir.rglob("*") if _.is_file())
    return {"ok": True, "out": str(dest_dir), "files": n}


def run_hash_file(path, out_txt=None):
    import hashlib
    path = Path(path)
    data = path.read_bytes()
    lines = [
        f"file={path}",
        f"size={len(data)}",
        f"md5={hashlib.md5(data).hexdigest()}",
        f"sha1={hashlib.sha1(data).hexdigest()}",
        f"sha256={hashlib.sha256(data).hexdigest()}",
    ]
    text = "\n".join(lines)
    if out_txt:
        Path(out_txt).write_text(text, encoding="utf-8")
    return {"ok": True, "report": text, "out": str(out_txt) if out_txt else None}


def run_string_scan(path, out_txt=None, min_len=4):
    path = Path(path)
    data = path.read_bytes()
    cur = bytearray()
    found = []
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                found.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        found.append(cur.decode("ascii", errors="ignore"))
    text = "\n".join(found[:5000])
    if out_txt:
        Path(out_txt).write_text(text, encoding="utf-8")
    return {"ok": True, "count": len(found), "out": str(out_txt) if out_txt else None}


def run_lua_bytecode_strings(input_path, out_dir):
    """Fallback: extract printable strings from Lua bytecode when JVM/ART unluac unavailable."""
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()
    strings = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append(cur.decode("ascii", errors="ignore"))
    # unique keep order
    seen = set()
    uniq = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    dest = out_dir / (input_path.stem + "_strings.txt")
    dest.write_text("\n".join(uniq[:8000]), encoding="utf-8")
    header_ok = data[:4] == b"\x1bLua"
    return {
        "ok": True,
        "mode": "strings_fallback",
        "lua_header": header_ok,
        "count": len(uniq),
        "out": str(dest),
        "note": "Full decompile needs ART unluac; this is string dump only",
    }


def is_luas_header(data: bytes) -> bool:
    """True if file starts with Lua 5.3-style header (including LuaS / slua variants)."""
    if len(data) < 12:
        return False
    if data[:4] != b"\x1bLua":
        return False
    return data[4] in (0x53, 0x51, 0x52, 0x54) or data[4:5] == b"S"


def extract_lua_constants(input_path, out_dir, max_strings=5000):
    """
    Walk Lua 5.3 bytecode after standard header and pull string/number constants.
    Works on many LuaS samples even when full unluac fails (custom opcodes / partial encrypt).
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()
    if not is_luas_header(data):
        return {"ok": False, "error": "not a Lua header", "magic": data[:8].hex()}

    strings = []
    i = 12
    n = len(data)
    while i + 5 < n:
        ln = int.from_bytes(data[i : i + 4], "little")
        if 2 <= ln <= 512 and i + 4 + ln <= n:
            chunk = data[i + 4 : i + 4 + ln]
            if chunk and chunk[-1] == 0:
                chunk = chunk[:-1]
            if chunk and all(32 <= b < 127 or b in (9, 10, 13) for b in chunk):
                try:
                    s = chunk.decode("utf-8", errors="strict")
                    if len(s) >= 2:
                        strings.append(s)
                    i += 4 + ln
                    continue
                except Exception:
                    pass
        i += 1

    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append(cur.decode("ascii", errors="ignore"))

    seen = set()
    uniq = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)

    dest = out_dir / (input_path.stem + "_constants.txt")
    dest.write_text("\n".join(uniq[:max_strings]), encoding="utf-8")
    return {
        "ok": True,
        "mode": "lua_constants",
        "count": len(uniq),
        "out": str(dest),
        "header": data[:16].hex(),
    }


def run_lua_multi_xor(input_path, out_dir, keys=None):
    """
    Try several common single-byte and short multi-byte XOR keys on body after header.
    Writes best candidates (highest printable ratio) for manual inspection / re-unluac.
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = bytearray(input_path.read_bytes())
    if len(data) < 32:
        return {"ok": False, "error": "file too small"}

    header_len = 56 if is_luas_header(data) else 0
    body = data[header_len:]

    if keys is None:
        keys = [
            bytes([0x11, 0x21, 0x36, 0x47]),
            bytes([0x18]),
            bytes([0x55]),
            bytes([0xAA]),
            bytes([0x5A]),
            bytes([0x00, 0x01, 0x02, 0x03]),
            b"ALVSIA",
            b"PUBGM",
            b"Tencent",
        ]

    results = []
    for key in keys:
        out = bytearray(body)
        for i in range(len(out)):
            out[i] ^= key[i % len(key)]
        printable = sum(1 for b in out if 32 <= b < 127)
        ratio = printable / max(1, len(out))
        cand = bytes(data[:header_len]) + bytes(out)
        name = f"{input_path.stem}_xor_{key.hex()[:16]}.bin"
        dest = out_dir / name
        dest.write_bytes(cand)
        results.append({"key": key.hex(), "ratio": round(ratio, 4), "out": str(dest)})

    results.sort(key=lambda x: -x["ratio"])
    return {"ok": True, "mode": "multi_xor", "candidates": results[:8], "best": results[0] if results else None}


def run_lua_smart(input_path, out_dir, jars_dir=None):
    """
    Unified LUA pipeline:
    1) detect LuaS header
    2) try unluac (jar / ART)
    3) on failure → constants + strings + multi-xor
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()
    report = {"file": str(input_path), "size": len(data), "steps": []}

    if not is_luas_header(data):
        report["steps"].append({"step": "detect", "ok": False, "note": "not Lua header"})
        r = run_lua_bytecode_strings(input_path, out_dir)
        report["steps"].append({"step": "strings", **r})
        return {"ok": True, "mode": "smart_nonlua", **report}

    report["steps"].append({"step": "detect", "ok": True, "header": data[:16].hex()})

    ur = run_unluac(input_path, out_dir, jars_dir=jars_dir)
    report["steps"].append({"step": "unluac", **ur})
    if ur.get("ok"):
        return {"ok": True, "mode": "smart_unluac", **report}

    cr = extract_lua_constants(input_path, out_dir)
    report["steps"].append({"step": "constants", **cr})

    sr = run_lua_bytecode_strings(input_path, out_dir)
    report["steps"].append({"step": "strings", **sr})

    xr = run_lua_multi_xor(input_path, out_dir)
    report["steps"].append({"step": "multi_xor", **{k: xr[k] for k in ("ok", "mode", "best") if k in xr}})

    return {
        "ok": True,
        "mode": "smart_fallback",
        "note": "unluac failed (custom opcode / encrypt body) — constants+strings+xor candidates written",
        **report,
    }


# ---------------------------------------------------------------------------
# REBRAND — string replace brand/watermark/channel (NO network, NO bot token)
# ---------------------------------------------------------------------------

# Known third-party watermarks / brands found in user-supplied packs
KNOWN_BRANDS = [
    "SRC_HUB",
    "@SRC_HUB",
    "t.me/SRC_HUB",
    "https://t.me/SRC_HUB",
    "http://t.me/SRC_HUB",
    "XThrlen",
    "@XThrlen",
    "ALECTO",
    "@ALECTO",
    "ALECTOGAMES",
    "HACKER420",
    "@HACKER420",
    "SKUY",
    "SKUYV5",
    "GSZV4",
    "GSZV",
    "Nadeem",
    "NADEEM",
    "GRW PREMIUM",
    "GRW",
    "AKMOD",
    "Myanmar VIP",
    "FREE PAK",
]

DEFAULT_BRAND = "ALVSIA PRO"
DEFAULT_CHANNEL = "t.me/ALVSIA_PRO"
DEFAULT_WATERMARK = "ALVSIA PRO | t.me/ALVSIA_PRO"


def _load_rebrand_config(out_root):
    """
    Manual override from WORK/rebrand_config.txt (key=value lines):
      brand=ALVSIA PRO
      channel=t.me/ALVSIA_PRO
      watermark=ALVSIA PRO | t.me/ALVSIA_PRO
    Missing keys fall back to defaults.
    """
    cfg = {
        "brand": DEFAULT_BRAND,
        "channel": DEFAULT_CHANNEL,
        "watermark": DEFAULT_WATERMARK,
    }
    p = Path(out_root) / "WORK" / "rebrand_config.txt"
    if p.is_file():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip().lower(), v.strip()
            if k in cfg and v:
                cfg[k] = v
    # keep watermark consistent if only brand/channel set
    if cfg["watermark"] == DEFAULT_WATERMARK and (
        cfg["brand"] != DEFAULT_BRAND or cfg["channel"] != DEFAULT_CHANNEL
    ):
        cfg["watermark"] = "%s | %s" % (cfg["brand"], cfg["channel"])
    return cfg


def _build_replace_map(cfg):
    """Map old brand tokens -> new brand / channel / watermark."""
    brand = cfg["brand"]
    channel = cfg["channel"]
    watermark = cfg["watermark"]
    # normalize channel forms
    ch_bare = channel.replace("https://", "").replace("http://", "").lstrip("/")
    if ch_bare.startswith("t.me/"):
        ch_at = "@" + ch_bare[5:]
        ch_url = "https://" + ch_bare
    elif ch_bare.startswith("@"):
        ch_at = ch_bare
        ch_url = "https://t.me/" + ch_bare[1:]
        ch_bare = "t.me/" + ch_bare[1:]
    else:
        ch_at = "@" + ch_bare
        ch_url = "https://t.me/" + ch_bare
        ch_bare = "t.me/" + ch_bare

    pairs = []
    # specific known full strings first (longest first)
    known_sorted = sorted(KNOWN_BRANDS, key=len, reverse=True)
    for old in known_sorted:
        low = old.lower()
        if "t.me/" in low or low.startswith("http"):
            pairs.append((old, ch_url if old.lower().startswith("http") else ch_bare))
        elif old.startswith("@"):
            pairs.append((old, ch_at if "hub" in low or "thrlen" in low or "alecto" in low else "@" + brand.replace(" ", "")))
        else:
            pairs.append((old, brand))
    # generic fallbacks
    pairs.append(("SRC_HUB", brand.replace(" ", "_")))
    pairs.append(("XThrlen", brand.replace(" ", "")))
    return pairs, watermark


def run_rebrand_scan(path, out_txt=None):
    """Scan file or directory for known brand strings. Report only."""
    path = Path(path)
    hits = []
    files = []
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = [f for f in path.rglob("*") if f.is_file() and f.stat().st_size < 50_000_000]
    else:
        return {"ok": False, "error": "path not found"}

    for f in files:
        try:
            data = f.read_bytes()
        except Exception:
            continue
        # try text decode for .lua/.txt/.ini; else raw search
        text = None
        if f.suffix.lower() in (".lua", ".txt", ".ini", ".json", ".xml", ".csv"):
            try:
                text = data.decode("utf-8")
            except Exception:
                try:
                    text = data.decode("latin-1")
                except Exception:
                    text = None
        for brand in KNOWN_BRANDS:
            b = brand.encode("utf-8")
            count = data.count(b)
            if count:
                hits.append({"file": str(f), "brand": brand, "count": count})
            if text and brand in text and not count:
                hits.append({"file": str(f), "brand": brand, "count": text.count(brand)})

    lines = ["ALVSIA REBRAND SCAN", "path=%s" % path, "hits=%s" % len(hits)]
    for h in hits[:200]:
        lines.append("%(count)s  %(brand)s  %(file)s" % h)
    report = "\n".join(lines)
    if out_txt:
        Path(out_txt).parent.mkdir(parents=True, exist_ok=True)
        Path(out_txt).write_text(report, encoding="utf-8")
    return {"ok": True, "hits": len(hits), "details": hits[:100], "out": str(out_txt) if out_txt else None, "report": report}


def run_rebrand_file(input_path, out_dir, out_root=None, brand=None, channel=None, watermark=None):
    """
    Rebrand a single text-like file (lua/txt/ini) or binary string-replace.
    Auto defaults to ALVSIA PRO; manual via args or WORK/rebrand_config.txt.
    Does NOT add network/Telegram bot calls.
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cfg = _load_rebrand_config(out_root or out_dir.parent.parent)
    if brand:
        cfg["brand"] = brand
    if channel:
        cfg["channel"] = channel
    if watermark:
        cfg["watermark"] = watermark
    elif brand or channel:
        cfg["watermark"] = "%s | %s" % (cfg["brand"], cfg["channel"])

    pairs, wm = _build_replace_map(cfg)
    data = input_path.read_bytes()
    original = data
    replaced = 0
    notes = []

    # Prefer UTF-8 text path for .lua source
    is_text = input_path.suffix.lower() in (".lua", ".txt", ".ini", ".json", ".xml", ".csv")
    if is_text:
        try:
            text = data.decode("utf-8")
            for old, new in pairs:
                if old in text:
                    c = text.count(old)
                    text = text.replace(old, new)
                    replaced += c
                    notes.append("%s x%d -> %s" % (old, c, new))
            # ensure watermark marker present once if file had any brand
            if replaced and wm and wm not in text and "WATERMARK" in text.upper():
                # leave structure; user can edit
                pass
            data = text.encode("utf-8")
        except Exception as e:
            notes.append("text-fail: %s — binary fallback" % e)
            is_text = False

    if not is_text:
        for old, new in pairs:
            ob, nb = old.encode("utf-8"), new.encode("utf-8")
            if ob in data:
                # same-length pad/truncate to avoid breaking binary offsets when possible
                if len(nb) < len(ob):
                    nb = nb + b" " * (len(ob) - len(nb))
                elif len(nb) > len(ob):
                    nb = nb[: len(ob)]
                c = data.count(ob)
                data = data.replace(ob, nb)
                replaced += c
                notes.append("%s x%d (bin len=%d)" % (old, c, len(ob)))

    dest = out_dir / (input_path.stem + "_rebrand" + input_path.suffix)
    dest.write_bytes(data)
    changed = data != original
    return {
        "ok": True,
        "mode": "rebrand_file",
        "brand": cfg["brand"],
        "channel": cfg["channel"],
        "watermark": cfg["watermark"],
        "replaced": replaced,
        "changed": changed,
        "out": str(dest),
        "notes": notes[:40],
        "note": "String rebrand only — no Telegram bot / no phone-home",
    }


def run_rebrand_tree(src_dir, out_dir, out_root=None, brand=None, channel=None, watermark=None):
    """Rebrand all text-like files under a directory (e.g. unpacked PAK tree)."""
    src_dir = Path(src_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not src_dir.is_dir():
        return {"ok": False, "error": "src not a directory"}

    results = []
    total_replaced = 0
    for f in src_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in (".lua", ".txt", ".ini", ".json", ".xml", ".csv", ".uasset", ".uexp"):
            # still try lua-named without suffix
            if b"\x1bLua" == f.read_bytes()[:4] if f.stat().st_size > 4 else False:
                pass
            elif f.suffix.lower() not in (".lua", ".txt", ".ini"):
                continue
        rel = f.relative_to(src_dir)
        dest_parent = out_dir / rel.parent
        dest_parent.mkdir(parents=True, exist_ok=True)
        r = run_rebrand_file(f, dest_parent, out_root=out_root, brand=brand, channel=channel, watermark=watermark)
        # write with original name under out tree
        final = dest_parent / f.name
        if Path(r["out"]).is_file():
            Path(r["out"]).replace(final)
            r["out"] = str(final)
        total_replaced += r.get("replaced", 0)
        if r.get("changed"):
            results.append(r)

    summary = out_dir / "_rebrand_report.txt"
    lines = [
        "ALVSIA REBRAND TREE",
        "src=%s" % src_dir,
        "files_changed=%s" % len(results),
        "total_replaced=%s" % total_replaced,
    ]
    for r in results[:100]:
        lines.append("%s replaced=%s" % (r.get("out"), r.get("replaced")))
    summary.write_text("\n".join(lines), encoding="utf-8")
    return {
        "ok": True,
        "mode": "rebrand_tree",
        "files_changed": len(results),
        "total_replaced": total_replaced,
        "out": str(out_dir),
        "report": str(summary),
        "note": "String rebrand only — no Telegram bot / no phone-home",
    }


def run_rebrand_auto(input_path, out_dir, out_root=None):
    """Convenience: auto ALVSIA PRO defaults on file or directory."""
    p = Path(input_path)
    if p.is_dir():
        return run_rebrand_tree(p, out_dir, out_root=out_root)
    return run_rebrand_file(p, out_dir, out_root=out_root)

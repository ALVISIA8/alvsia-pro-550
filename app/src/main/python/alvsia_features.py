# -*- coding: utf-8 -*-
"""ALVSIA PRO 5.5 — features: LUA (unluac jar), helpers."""
from __future__ import annotations
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from lua_engine import detect_lua, analyze_lua, decompile_lua, validate_lua_source, transform_bgmi_lua, unwrap_lua_container
from lua_engine.engine import clean_lua_source
try:
    from lua_engine.decompiler53 import decompile_file as _decompile53_file
except Exception as _e53:
    _decompile53_file = None
try:
    from lua_output_validator import validate_decompile_text, classify_bytes
except Exception:
    validate_decompile_text = None
    classify_bytes = None
try:
    from lua_engine.vm_deobfuscator import detect_vm_obfuscation, extract_vm_payload
    _VM_DEOBF = True
except Exception:
    _VM_DEOBF = False
    detect_vm_obfuscation = None
    extract_vm_payload = None
try:
    from lua_engine.luajit_decompiler import disassemble_luajit, detect_luajit
    _LUAJIT = True
except Exception:
    _LUAJIT = False
    disassemble_luajit = None
    detect_luajit = None
try:
    from lua_engine.multi_format import detect_format, run_universal_smart as _run_universal
    _MULTI_FORMAT = True
except Exception:
    _MULTI_FORMAT = False
    detect_format = None
    _run_universal = None


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


def _prepare_lua_input(input_path, out_dir):
    input_path = Path(input_path); out_dir = Path(out_dir)
    raw = input_path.read_bytes()
    if not raw.startswith(b"\x78\xda"):
        return input_path, None
    payload, ci = unwrap_lua_container(raw)
    if not payload.startswith((b"\x1bLua", b"\x1bLJ")):
        raise ValueError("compressed input did not contain Lua/LuaJIT bytecode")
    normalized = out_dir / (input_path.stem + "_unwrapped.luac")
    normalized.write_bytes(payload)
    return normalized, ci

def run_unluac(input_path, out_dir, jars_dir=None, mode="decompile"):
    """Decompile Lua bytecode with strict exit/output validation and container unwrapping."""
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        normalized, ci = _prepare_lua_input(input_path, out_dir)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    jar = _pick_jar(jars_dir)
    if jar is None:
        return {"ok": False, "error": "unluac jar missing — place unluac.jar in jars dir",
                **({"unwrapped": str(normalized)} if ci else {})}
    java = _find_java()
    if not java:
        dest = out_dir / (input_path.stem + "_NEED_JAVA.txt")
        dest.write_text("Java runtime unavailable.\nJar: %s\nInput: %s\n" % (jar, normalized), encoding="utf-8")
        return {"ok": False, "error": "Java runtime not found on device", "jar": str(jar),
                "hint": str(dest), **({"unwrapped": str(normalized)} if ci else {})}
    out_lua = out_dir / (input_path.stem + "_decompiled.lua")
    try:
        proc = subprocess.run([java, "-jar", str(jar), str(normalized)],
                              capture_output=True, timeout=120)
        stdout = (proc.stdout or b"").decode("utf-8", "replace")
        stderr = (proc.stderr or b"").decode("utf-8", "replace")
        if proc.returncode != 0 or not stdout.strip():
            out_lua.unlink(missing_ok=True)
            return {"ok": False, "error": stderr.strip()[:1200] or "unluac returned no source",
                    "code": proc.returncode, "jar": str(jar),
                    **({"unwrapped": str(normalized), "container": ci.format} if ci else {})}
        out_lua.write_text(stdout, encoding="utf-8")
        valid, msg = validate_lua_source(out_lua)
        if not valid:
            out_lua.unlink(missing_ok=True)
            return {"ok": False, "error": "Lua validation failed: " + msg, "code": proc.returncode,
                    "jar": str(jar), **({"unwrapped": str(normalized)} if ci else {})}
        return {"ok": True, "out": str(out_lua), "code": proc.returncode, "jar": str(jar),
                "validation": msg, **({"unwrapped": str(normalized), "container": ci.format,
                "container_chunks": ci.chunks} if ci else {})}
    except Exception as e:
        return {"ok": False, "error": str(e), "jar": str(jar),
                **({"unwrapped": str(normalized)} if ci else {})}


def run_lua_xor(input_path, out_dir, key_hex=None):
    """XOR preview against normalized Lua payload when a container is present."""
    input_path=Path(input_path); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    try: normalized, ci = _prepare_lua_input(input_path,out_dir)
    except Exception as exc: return {"ok":False,"error":str(exc)}
    data=normalized.read_bytes()
    try: key=bytes.fromhex(key_hex) if key_hex else bytes([0x11,0x21,0x36,0x47])
    except ValueError: return {"ok":False,"error":"invalid XOR key hex"}
    out=bytes(data[i]^key[i%len(key)] for i in range(len(data)))
    dest=out_dir/(input_path.name+".xor"); dest.write_bytes(out)
    return {"ok":True,"out":str(dest),"bytes":len(out),**({"container":ci.format,"normalized":str(normalized)} if ci else {})}


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
    """Extract printable strings from normalized Lua bytecode/container."""
    input_path=Path(input_path); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    try: normalized, ci = _prepare_lua_input(input_path,out_dir)
    except Exception as exc: return {"ok":False,"error":str(exc)}
    data=normalized.read_bytes(); strings=[]; cur=bytearray()
    for b in data:
        if 32<=b<127 or b in (9,): cur.append(b)
        else:
            if len(cur)>=4: strings.append(cur.decode("ascii","ignore"))
            cur.clear()
    if len(cur)>=4: strings.append(cur.decode("ascii","ignore"))
    seen=set(); uniq=[]
    for value in strings:
        if value not in seen: seen.add(value); uniq.append(value)
    dest=out_dir/(input_path.stem+"_strings.txt")
    dest.write_text("\n".join(uniq[:8000]),encoding="utf-8")
    return {"ok":True,"mode":"strings_fallback","lua_header":data[:4]==b"\x1bLua",
            "count":len(uniq),"out":str(dest),
            "note":"Full decompile requires a compatible Lua decompiler; strings were extracted from normalized payload",
            **({"container":ci.format,"container_chunks":ci.chunks,"normalized":str(normalized)} if ci else {})}


def is_luas_header(data: bytes) -> bool:
    """True if file starts with Lua 5.3-style header (including LuaS / slua variants)."""
    if len(data) < 12:
        return False
    if data[:4] != b"\x1bLua":
        return False
    return data[4] in (0x53, 0x51, 0x52, 0x54) or data[4:5] == b"S"


def extract_lua_constants(input_path, out_dir, max_strings=5000):
    """Extract likely constants from Lua bytecode, including wrapped containers."""
    input_path=Path(input_path); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    try: normalized, ci = _prepare_lua_input(input_path,out_dir)
    except Exception as exc: return {"ok":False,"error":str(exc)}
    data=normalized.read_bytes()
    if not is_luas_header(data): return {"ok":False,"error":"not a Lua header","magic":data[:8].hex()}
    strings=[]; i=12; n=len(data)
    while i+5<n:
        ln=int.from_bytes(data[i:i+4],"little")
        if 2<=ln<=4096 and i+4+ln<=n:
            chunk=data[i+4:i+4+ln]
            if chunk and chunk[-1]==0: chunk=chunk[:-1]
            if chunk and all(32<=b<127 or b in (9,10,13) for b in chunk):
                try:
                    value=chunk.decode("utf-8","strict")
                    if len(value)>=2: strings.append(value); i+=4+ln; continue
                except UnicodeDecodeError: pass
        i+=1
    cur=bytearray()
    for b in data:
        if 32<=b<127: cur.append(b)
        else:
            if len(cur)>=4: strings.append(cur.decode("ascii","ignore"))
            cur.clear()
    if len(cur)>=4: strings.append(cur.decode("ascii","ignore"))
    seen=set(); uniq=[]
    for value in strings:
        if value not in seen: seen.add(value); uniq.append(value)
    dest=out_dir/(input_path.stem+"_constants.txt"); dest.write_text("\n".join(uniq[:max_strings]),encoding="utf-8")
    return {"ok":True,"mode":"lua_constants","count":len(uniq),"out":str(dest),"header":data[:16].hex(),
            **({"container":ci.format,"container_chunks":ci.chunks,"normalized":str(normalized)} if ci else {})}


def run_lua_multi_xor(input_path, out_dir, keys=None):
    """
    Try several common single-byte and short multi-byte XOR keys on body after header.
    Writes best candidates (highest printable ratio) for manual inspection / re-unluac.
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        normalized, ci = _prepare_lua_input(input_path, out_dir)
    except Exception:
        normalized, ci = input_path, None
    data = bytearray(normalized.read_bytes())
    if len(data) < 32:
        return {"ok": False, "error": "file too small"}

    # Lua 5.1-5.4 headers are followed by the main-function upvalue count.
    header_len = 34 if is_luas_header(data) else 0
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
    1) detect LuaS header / unwrap container
    2) pure-Python Lua 5.3 decompiler (no Java needed — works on Android)
    3) try unluac jar if Java available
    4) on failure → constants + strings + multi-xor
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()
    report = {"file": str(input_path), "size": len(data), "steps": []}
    info = detect_lua(input_path)
    if info.kind == "unknown":
        report["steps"].append({"step": "detect", "ok": False, "note": "not recognized Lua/source/container"})
        r = run_lua_bytecode_strings(input_path, out_dir)
        report["steps"].append({"step": "strings", **r})
        return {"ok": False, "mode": "smart_nonlua", **report}
    report["steps"].append({"step": "detect", "ok": True, "format": info.format,
                             "version": info.version, "wrapped": info.wrapped,
                             "container": info.container, "chunks": info.container_chunks})

    # ── Step 1: unwrap container if needed ──────────────────────────────────
    work_input = input_path
    if info.wrapped:
        try:
            payload, ci = unwrap_lua_container(data)
            unwrapped_path = out_dir / (input_path.stem + "_unwrapped.luac")
            unwrapped_path.write_bytes(payload)
            work_input = unwrapped_path
            report["steps"].append({"step": "unwrap", "ok": True, "container": ci.format,
                                     "chunks": ci.chunks, "out": str(unwrapped_path)})
        except Exception as e:
            report["steps"].append({"step": "unwrap", "ok": False, "error": str(e)})

    # ── Step 2: pure-Python Lua 5.3 decompiler (primary — no Java) ─────────
    work_data = work_input.read_bytes()
    is_lua53 = (len(work_data) > 4 and
                work_data[:4] == b"\x1bLua" and
                work_data[4] == 0x53)
    bgmi_normalized = False
    bgmi_key_available = False
    bgmi_detected = False
    if is_lua53:
        try:
            from lua_engine.bgmi import is_bgmi_lua
            bgmi_detected = is_bgmi_lua(work_data)
        except Exception as e:
            report["steps"].append({"step": "bgmi_detect", "ok": False, "error": str(e)})
    if bgmi_detected:
        # BGMI bytecode has custom opcodes, delta line info and 32-bit string
        # lengths. Convert the structure before either decompiler is allowed
        # to treat the data as standard Lua 5.3.
        key_hex = os.environ.get("SERVER_LUA_XOR_KEY_HEX", "").strip()
        key_file = out_dir.parent.parent / "LUA_TOOL" / "lua_xor_key.txt"
        if not key_hex and key_file.is_file():
            try:
                key_hex = key_file.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                key_hex = ""
        key = b""
        if key_hex:
            try:
                key = bytes.fromhex(key_hex)
                bgmi_key_available = bool(key)
            except ValueError:
                report["steps"].append({"step": "bgmi_key", "ok": False,
                                        "error": "Lua XOR key is not valid hexadecimal; using structure-only normalization"})
        try:
            from lua_engine.bgmi import transform_bgmi_lua
            normalized = transform_bgmi_lua(work_data, key, decrypt=True)
            normalized_path = out_dir / (input_path.stem + "_bgmi_normalized.luac")
            normalized_path.write_bytes(normalized)
            work_input = normalized_path
            work_data = normalized
            bgmi_normalized = True
            report["bgmi_normalized"] = True
            report["strings_decrypted"] = bgmi_key_available
            report["note"] = (
                "BGMI Lua structure/opcodes normalized and XOR strings decrypted."
                if bgmi_key_available else
                "BGMI Lua structure/opcodes normalized; XOR-encrypted strings remain opaque because no Lua XOR key was available."
            )
            report["steps"].append({
                "step": "bgmi_normalize", "ok": True,
                "out": str(normalized_path),
                "strings_decrypted": bgmi_key_available,
            })
        except Exception as e:
            report["steps"].append({"step": "bgmi_normalize", "ok": False, "error": str(e)})
            return {
                "ok": False, "mode": "bgmi_normalization_failed",
                "error": "BGMI-specific bytecode normalization failed; standard decompilation was not attempted on unnormalized opcodes.",
                **report,
            }
    is_luajit = (len(work_data) > 3 and
                 work_data[:3] == b"\x1bLJ" and
                 work_data[3] in (0x01, 0x02))

    # ── Step 2a: LuaJIT disassembler ────────────────────────────────────────
    if _LUAJIT and is_luajit:
        try:
            out_lua = out_dir / (input_path.stem + "_ljbc.lua")
            lr = disassemble_luajit(work_input, out_lua)
            report["steps"].append({"step": "luajit_disasm", **lr})
            if lr.get("ok"):
                report["ok"] = True
                return {"ok": True, "mode": "smart_luajit", "out": str(out_lua),
                        "lines": lr.get("lines", 0), **report}
        except Exception as e:
            report["steps"].append({"step": "luajit_disasm", "ok": False, "error": str(e)})

    if _decompile53_file is not None and is_lua53:
        try:
            out_lua = out_dir / (input_path.stem + "_decompiled.lua")
            pr = _decompile53_file(work_input, out_lua)
            report["steps"].append({"step": "py_decompile53", **pr})
            if pr.get("ok") and out_lua.exists() and out_lua.stat().st_size > 0:
                # Quick sanity: file must contain at least one Lua keyword
                snippet = out_lua.read_text(encoding="utf-8", errors="replace")[:4096]
                import re as _re
                has_lua = bool(_re.search(r'\b(local|function|return|if|for|while|end)\b', snippet))
                if has_lua:
                    # ── Step 2b: VM obfuscation check ───────────────────────
                    vm_info = {}
                    if _VM_DEOBF:
                        try:
                            obf = detect_vm_obfuscation(work_input)
                            vm_info["vm_obfuscated"] = obf.is_obfuscated
                            vm_info["vm_confidence"] = obf.confidence
                            vm_info["vm_notes"] = obf.notes
                            vm_info["vm_main_proto_instr"] = obf.main_proto_instr
                            vm_info["vm_max_reg"] = obf.max_reg
                            if obf.is_obfuscated:
                                # Attempt payload extraction + re-decompile
                                vr = extract_vm_payload(work_input, out_dir)
                                vm_info["vm_extract"] = vr
                                # Use "vm_note" step (no ok=False) so UI shows SUCCESS for the
                                # overall decompile even when dynamic VM payload is unrecoverable.
                                report["steps"].append({
                                    "step": "vm_note",
                                    "detected": True,
                                    "partial": vr.get("partial", True),
                                    "mode": vr.get("mode", "dynamic_vm"),
                                    "note": vr.get("note", "runtime VM — static payload extraction not possible"),
                                })
                                if vr.get("ok"):
                                    recovered = Path(vr["out"])
                                    # Re-decompile recovered payload
                                    out_recovered = out_dir / (input_path.stem + "_recovered.lua")
                                    pr2 = _decompile53_file(recovered, out_recovered)
                                    vm_info["vm_decompiled"] = pr2
                                    report["steps"].append({"step": "py_decompile53_recovered", **pr2})
                                    if pr2.get("ok"):
                                        return {"ok": True, "mode": "smart_py53_vm_recovered",
                                                "out": str(out_recovered),
                                                "lines": pr2.get("lines", 0),
                                                "note": "VM obfuscation detected and payload successfully recovered",
                                                **vm_info, **report}
                        except Exception as ve:
                            vm_info["vm_check_error"] = str(ve)
                    report["ok"] = True
                    return {"ok": True,
                            "mode": ("smart_bgmi_py53" if bgmi_normalized else "smart_py53"),
                            "out": str(out_lua), "lines": pr.get("lines", 0),
                            **vm_info, **report}
        except Exception as e:
            report["steps"].append({"step": "py_decompile53", "ok": False, "error": str(e)})

    # ── Step 3: unluac jar (fallback — needs Java, works in Termux) ─────────
    ur = run_unluac(work_input, out_dir, jars_dir=jars_dir)
    report["steps"].append({"step": "unluac", **ur})
    if ur.get("ok"):
        return {"ok": True,
                "mode": ("smart_bgmi_unluac" if bgmi_normalized else "smart_unluac"),
                **ur, **report}

    # ── Step 4: partial recovery ─────────────────────────────────────────────
    cr = extract_lua_constants(input_path, out_dir)
    report["steps"].append({"step": "constants", **cr})

    sr = run_lua_bytecode_strings(input_path, out_dir)
    report["steps"].append({"step": "strings", **sr})

    xr = run_lua_multi_xor(input_path, out_dir)
    report["steps"].append({"step": "multi_xor", **{k: xr[k] for k in ("ok", "mode", "best") if k in xr}})

    # Honest final status: never SUCCESS decompile without validated source
    final_status = "PARTIAL"
    if validate_decompile_text is not None:
        # scan any .lua written in out_dir
        for cand in out_dir.glob("*_decompiled.lua"):
            v = validate_decompile_text(cand.read_text(encoding="utf-8", errors="replace"))
            report["steps"].append({"step": "validate_source", "file": str(cand), **v})
            if v.get("is_lua_source"):
                final_status = "SUCCESS"
                report["ok"] = True
                break
        else:
            # strings file is recovery only
            for cand in out_dir.glob("*_strings.txt"):
                v = validate_decompile_text(cand.read_text(encoding="utf-8", errors="replace"))
                report["steps"].append({"step": "validate_strings", "file": str(cand), **v})
            final_status = "PARTIAL"

    stage_path = out_dir / (input_path.stem + "_STAGE_REPORT.txt")
    lines = [
        "ALVISIA PRO LUA STAGE REPORT",
        "file=%s" % input_path,
        "size=%s" % report.get("size"),
        "final_status=%s" % final_status,
        "mode=smart_fallback",
        "note=py_decompile53 + unluac both failed — recovery artifacts only",
        "",
    ]
    for st in report.get("steps") or []:
        lines.append(str(st))
    stage_path.write_text("\n".join(lines), encoding="utf-8")
    report["stage_report"] = str(stage_path)
    report["final_status"] = final_status

    return {
        "ok": final_status == "SUCCESS",
        "mode": "smart_fallback",
        "final_status": final_status,
        "note": "PARTIAL: detect/unpack/strings may exist; decompile source NOT validated",
        **report,
    }



# ---------------------------------------------------------------------------
# LUA ENGINE v5.5 — unified detection / analysis / fallback
# ---------------------------------------------------------------------------

def run_lua_universal(input_path, out_dir, jars_dir=None):
    """Single deterministic LUA entry point used by the Android bridge."""
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        analysis = analyze_lua(input_path, out_dir)
        if not analysis.get("ok"):
            # Unknown input is not a successful LUA operation.
            return analysis

        info = detect_lua(input_path)
        report_path = out_dir / (input_path.stem + "_analysis.json")
        import json
        report_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")

        result = decompile_lua(input_path, out_dir, jars_dir=jars_dir)
        result["analysis"] = analysis
        result["report"] = str(report_path)

        # A successful decompile must have a validated Lua source file.
        if result.get("ok") and result.get("out"):
            valid, msg = validate_lua_source(result["out"])
            result["validation"] = msg
            if not valid:
                result["ok"] = False
                result["error"] = "output validation failed: " + msg
                try:
                    Path(result["out"]).unlink()
                except Exception:
                    pass
        if not result.get("ok"):
            # Static artifacts remain useful even when no decompiler is available.
            strings = run_lua_bytecode_strings(input_path, out_dir)
            result["fallback_strings"] = strings
            result["note"] = (
                "Decompile unavailable; analysis/report/string artifacts were generated. "
                "No false SUCCESS was reported."
            )
        return result
    except Exception as exc:
        return {"ok": False, "error": str(exc), "mode": "universal"}

def run_lua_analysis(input_path, out_dir):
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    import json
    try:
        report = analyze_lua(input_path, out_dir)
        dest = out_dir / (input_path.stem + "_analysis.json")
        dest.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        report["out"] = str(dest)
        return report
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def run_lua_clean(input_path, out_dir):
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if detect_lua(input_path).kind != "source":
        return {"ok": False, "error": "source Lua text is required for cleanup"}
    dest = out_dir / (input_path.stem + "_clean.lua")
    try:
        return clean_lua_source(input_path, dest)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def run_pubg_lua_decrypt(input_path, out_dir, key_hex=None):
    """Decode the ALVISIA/BGMI Lua bytecode transform when an explicit key is supplied."""
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_hex = key_hex or os.environ.get("SERVER_LUA_XOR_KEY_HEX", "").strip()
    key_file = out_dir.parent.parent / "LUA_TOOL" / "lua_xor_key.txt"
    if not key_hex and key_file.is_file():
        key_hex = key_file.read_text(encoding="utf-8", errors="replace").strip()
    if not key_hex:
        return {"ok": False, "error": "Lua XOR key is required for BGMI transform"}
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return {"ok": False, "error": "Lua XOR key is not valid hexadecimal"}
    try:
        raw = input_path.read_bytes()
        out = transform_bgmi_lua(raw, key, decrypt=True)
        dest = out_dir / (input_path.stem + "_decrypted.luac")
        dest.write_bytes(out)
        return {
            "ok": True, "mode": "bgmi-lua-transform",
            "out": str(dest), "bytes": len(out),
            "lua_header": out[:8].hex(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

# ---------------------------------------------------------------------------
# UNIVERSAL — run_any_file: handles ALL formats, not just Lua
# ---------------------------------------------------------------------------

def run_any_file(input_path, out_dir, jars_dir=None):
    """
    ALVSIA PRO universal file handler.
    Detects the format of ANY file and routes to the best available tool:
      - Lua 5.1/5.2/5.3/5.4 bytecode → decompile (Python or Java)
      - LuaJIT bytecode → disassemble
      - VM-obfuscated Lua → detect + extract + re-decompile
      - zlib/gzip/lz4/zstd/bz2/xz compressed → decompress then re-process
      - ZIP/APK/PAK/JAR archives → extract Lua files, decompile each
      - Unity AssetBundle → scan for embedded Lua
      - ELF/PE/DEX binaries → scan for embedded Lua bytecode
      - Plain Lua source → validate + copy
      - Unknown → extract strings + brute-scan

    Returns {"ok": True/False, "mode": str, "out": str, ...}
    """
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if _MULTI_FORMAT and _run_universal is not None:
        # Full universal pipeline
        return _run_universal(input_path, out_dir, jars_dir=jars_dir)

    # Fallback if multi_format not available: route by extension/magic
    data = input_path.read_bytes()[:8]
    if data[:4] == b"\x1bLua":
        return run_lua_smart(input_path, out_dir, jars_dir=jars_dir)
    if data[:3] == b"\x1bLJ":
        return run_lua_smart(input_path, out_dir, jars_dir=jars_dir)
    if data[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        # zlib — decompress and re-run
        import zlib
        try:
            raw = input_path.read_bytes()
            dec = zlib.decompress(raw)
            dec_path = out_dir / (input_path.stem + "_decompressed.bin")
            dec_path.write_bytes(dec)
            return run_any_file(dec_path, out_dir, jars_dir)
        except Exception as e:
            return {"ok": False, "error": f"zlib decompress failed: {e}"}
    if data[:2] == b"PK":
        # ZIP-based
        import zipfile
        extracted = []
        try:
            with zipfile.ZipFile(input_path, "r") as z:
                for name in z.namelist():
                    if name.lower().endswith((".lua", ".luac", ".ljbc", ".bytes")):
                        blob = z.read(name)
                        p = out_dir / name.replace("/", "__")
                        p.write_bytes(blob)
                        extracted.append(p)
        except Exception:
            pass
        if extracted:
            results = [run_any_file(p, out_dir, jars_dir) for p in extracted[:20]]
            ok_count = sum(1 for r in results if r.get("ok"))
            return {"ok": ok_count > 0, "mode": "archive_fallback",
                    "extracted": len(extracted), "ok_count": ok_count}
        return {"ok": False, "error": "no Lua files in archive"}

    # Last resort: smart string scan
    return run_lua_bytecode_strings(input_path, out_dir)


def run_vm_deobf(input_path, out_dir):
    """
    Dedicated VM-deobfuscation entry point.
    Detects custom VM obfuscation in a Lua 5.3 file and attempts payload recovery.
    """
    input_path = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not _VM_DEOBF:
        return {"ok": False, "error": "vm_deobfuscator module not available"}

    det = detect_vm_obfuscation(input_path)
    if not det.is_obfuscated:
        return {"ok": False, "error": "file does not appear to be VM-obfuscated",
                "confidence": det.confidence, "notes": det.notes,
                "main_proto_instr": det.main_proto_instr}

    # Attempt extraction
    vr = extract_vm_payload(input_path, out_dir)
    if not vr.get("ok"):
        return {"ok": False, "vm_detected": True, "confidence": det.confidence,
                "notes": det.notes, **vr}

    # Re-decompile recovered payload
    recovered = Path(vr["out"])
    if _decompile53_file and recovered.stat().st_size > 32:
        out_dec = out_dir / (input_path.stem + "_vm_decompiled.lua")
        pr = _decompile53_file(recovered, out_dec)
        return {"ok": pr.get("ok", False), "mode": "vm_deobf_decompile",
                "vm_detected": True, "confidence": det.confidence,
                "vm_notes": det.notes, "vm_extract": vr,
                "decompile": pr, "out": str(out_dec) if pr.get("ok") else None}

    return {"ok": True, "mode": "vm_payload_extracted",
            "vm_detected": True, "confidence": det.confidence,
            "out": str(recovered), "note": "payload extracted but decompiler unavailable", **vr}


def run_format_detect(input_path):
    """Detect file format and return a detailed FormatInfo dict."""
    input_path = Path(input_path)
    if _MULTI_FORMAT and detect_format is not None:
        fi = detect_format(input_path)
        return {"ok": True, "fmt": fi.fmt, "category": fi.category,
                "lua_version": fi.lua_version, "compressed": fi.compressed,
                "container": fi.container, "notes": fi.notes,
                "magic_hex": fi.magic_hex, "size": fi.size}
    # Fallback: just read magic
    data = input_path.read_bytes()[:16]
    return {"ok": True, "magic_hex": data.hex(), "size": input_path.stat().st_size}


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


# ── Missing features added for full 17-module coverage ──────────────────────

def run_lua_analyze(input_path, out_dir):
    """Analyze Lua/LuaJIT bytecode: format detection + obfuscation report."""
    from pathlib import Path
    p = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = p.read_bytes()
    report_lines = ["ALVSIA LUA ANALYZER", "file=%s" % p.name, "size=%s bytes" % len(raw)]
    # Detect format
    if raw[:4] == b"\x1bLua":
        ver_byte = raw[4] if len(raw) > 4 else 0
        ver = "Lua5.1" if ver_byte == 0x51 else "Lua5.2" if ver_byte == 0x52 else "Lua5.3" if ver_byte == 0x53 else "Lua5.4" if ver_byte == 0x54 else "LuaUnknown(0x%02x)" % ver_byte
        report_lines.append("format=%s bytecode" % ver)
    elif raw[:4] == b"\x1bLJs":
        report_lines.append("format=LuaJIT bytecode")
    elif len(raw) > 4 and raw[0] == 0x1b and raw[1:4] == b"LJ\x02":
        report_lines.append("format=LuaJIT2")
    elif b"function" in raw[:200] or b"local" in raw[:200]:
        report_lines.append("format=Lua source (plaintext)")
    else:
        report_lines.append("format=unknown/binary blob")
    # XOR probe
    xor_candidates = []
    for k in range(1, 256):
        dec = bytes(b ^ k for b in raw[:64])
        if dec[:4] in (b"\x1bLua", b"\x1bLJs"):
            xor_candidates.append("0x%02x" % k)
    if xor_candidates:
        report_lines.append("xor_layer_candidates=%s" % ",".join(xor_candidates))
    else:
        report_lines.append("xor_layer=none_detected")
    # String density (obfuscation indicator)
    printable = sum(1 for b in raw if 32 <= b <= 126)
    density = printable / max(len(raw), 1)
    report_lines.append("printable_density=%.2f%%" % (density * 100))
    if density < 0.15:
        report_lines.append("obfuscation=HIGH (low string density)")
    elif density < 0.35:
        report_lines.append("obfuscation=MEDIUM")
    else:
        report_lines.append("obfuscation=LOW (readable)")
    out_file = out_dir / (p.stem + "_analysis.txt")
    out_file.write_text("\n".join(report_lines), encoding="utf-8")
    return {"ok": True, "out": str(out_file), "report": "\n".join(report_lines[:6])}


def run_lua_constants(input_path, out_dir):
    """Extract string constants and numbers from Lua bytecode."""
    from pathlib import Path
    import re
    p = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = p.read_bytes()
    strings = []
    cur = bytearray()
    for b in raw:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append(cur.decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append(cur.decode("ascii", errors="replace"))
    strings = list(dict.fromkeys(strings))  # dedupe preserving order
    out_file = out_dir / (p.stem + "_constants.txt")
    out_file.write_text("\n".join(strings), encoding="utf-8")
    return {"ok": True, "count": len(strings), "out": str(out_file)}


def run_obb_extract(input_path, out_dir):
    """Extract OBB/ZIP to out_dir."""
    import zipfile
    from pathlib import Path
    p = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(p, "r") as zf:
            zf.extractall(out_dir)
            count = len(zf.namelist())
        return {"ok": True, "extracted": count, "out": str(out_dir)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def run_obb_rezip(input_path, out_file):
    """Repack a folder (or file) into a .obb ZIP."""
    import zipfile
    from pathlib import Path
    p = Path(input_path); out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if p.is_dir():
        files = [f for f in p.rglob("*") if f.is_file()]
        with zipfile.ZipFile(out_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.write(f, f.relative_to(p))
        return {"ok": True, "packed": len(files), "out": str(out_file)}
    elif p.is_file():
        import shutil
        shutil.copy2(p, out_file)
        return {"ok": True, "packed": 1, "out": str(out_file), "note": "single file copied"}
    return {"ok": False, "error": "input not found"}


def run_strings_scan(input_path, out_dir):
    """Extract printable ASCII strings from any binary."""
    from pathlib import Path
    p = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = p.read_bytes()
    strings = []
    cur = bytearray()
    for b in raw:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append(cur.decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append(cur.decode("ascii", errors="replace"))
    strings = list(dict.fromkeys(strings))
    out_file = out_dir / ("strings_%s.txt" % p.stem)
    out_file.write_text("\n".join(strings), encoding="utf-8")
    return {"ok": True, "count": len(strings), "out": str(out_file)}


def run_export_report(input_path, out_dir):
    """Generate file info summary report."""
    import hashlib
    from pathlib import Path
    p = Path(input_path); out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = p.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()
    sha1 = hashlib.sha1(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()
    lines = [
        "ALVSIA FILE REPORT",
        "name=%s" % p.name,
        "size=%s bytes" % len(raw),
        "MD5=%s" % md5,
        "SHA1=%s" % sha1,
        "SHA256=%s" % sha256,
        "head_hex=%s" % raw[:16].hex(),
    ]
    # ZIP/OBB detection
    import zipfile
    if raw[:2] == b"PK":
        try:
            with zipfile.ZipFile(p) as zf:
                lines.append("type=ZIP/OBB entries=%s" % len(zf.namelist()))
        except Exception:
            lines.append("type=ZIP(corrupt)")
    elif raw[:4] == b"\x1bLua":
        lines.append("type=Lua bytecode")
    elif raw[:7] == b"\x04\x22\x4d\x18" or raw[:4] == b"\x28\xb5\x2f\xfd":
        lines.append("type=Zstd compressed")
    else:
        lines.append("type=binary/unknown")
    out_file = out_dir / ("report_%s.txt" % p.stem)
    out_file.write_text("\n".join(lines), encoding="utf-8")
    return {"ok": True, "out": str(out_file), "sha256": sha256}

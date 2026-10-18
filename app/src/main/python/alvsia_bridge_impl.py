# -*- coding: utf-8 -*-
"""
ALVSIA PRO 5.5.0 — bridge for 18-module catalog.
Modules 1-9: original. Modules 10-18: new in v5.5.0.
"""
from __future__ import annotations
import os
import re
import shutil
import traceback
import json
import hashlib
from pathlib import Path

# SECURITY: require native session marker plus 256-bit token shape (key login only).
# This is defense-in-depth, not a substitute for server-signed operation grants.

def _valid_apk_session():
    if os.environ.get("ALVSIA_APK_SESSION") != "1":
        return False
    try:
        from com.alvsia.pro.sec import SessionGate
        return bool(SessionGate.isSessionAuthorized())
    except Exception:
        return False

def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    lines = []
    try:
        # Hard gate
        if not _valid_apk_session():
            return "X AUTH: no valid APK session — login with your key first"
        lines.append("ALVSIA PRO 5.5.0 PREMIUM · engine")
        lines.append("m=%s sub=%s" % (module_id, sub_id))
        import alvsia_core as core
        import alvsia_features as feat

        out = Path(str(out_root))
        out.mkdir(parents=True, exist_ok=True)
        jars = Path(str(jars_dir)) if jars_dir else out / "jars"
        ip = str(input_path or "")
        mid = int(module_id)
        sid = str(sub_id)

        def need_file():
            if not ip or not Path(ip).exists():
                lines.append("X input missing")
                return False
            return True

        def work_dir():
            d = out / "WORK"
            d.mkdir(parents=True, exist_ok=True)
            return d

        def read_config(name: str):
            """Read a simple key=value config, also accepting JSON objects."""
            path = work_dir() / name
            if not path.is_file():
                return {}
            raw = path.read_text(encoding="utf-8", errors="replace").strip()
            if not raw:
                return {}
            if raw.startswith("{"):
                try:
                    value = json.loads(raw)
                    if isinstance(value, dict):
                        return {str(k).strip(): str(v).strip() for k, v in value.items()}
                except Exception:
                    pass
            values = {}
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip().lower()] = value.strip()
            return values

        def out_dir(name: str):
            d = out / "OUT" / name
            d.mkdir(parents=True, exist_ok=True)
            return d

        # ── 1  PAK Unpack ────────────────────────────────────────────────
        if mid == 1 or sid.startswith("pak_full") or sid in ("pak_list", "pak_info", "pak_csv"):
            if not need_file(): return "\n".join(lines)
            try:
                raw = Path(ip).read_bytes()
                lines.append("preflight size=%s head=%s" % (len(raw), raw[:8].hex()))
                if len(raw) < 64:
                    lines.append("X File too small for PAK/LuaS")
                    return "\n".join(lines)
                if raw[:4] == b"\x1bLua":
                    lines.append("NOTE: magic LuaS bytecode (NOT a PAK) -> LUA smart")
                    dest = out_dir("LUA")
                    r = feat.run_lua_smart(ip, dest, jars_dir=jars)
                    if r.get("ok"):
                        lines.append("OK mode=%s lines=%s" % (r.get("mode","?"), r.get("lines",0)))
                        lines.append("OUT -> %s" % r.get("out","(see OUT/LUA/)"))
                        if r.get("note"):
                            lines.append("NOTE: %s" % r.get("note"))
                        if r.get("strings_decrypted") is False:
                            lines.append("WARN: bytecode structure was decompiled, but protected string constants were not fully restored")
                        if r.get("vm_obfuscated"):
                            lines.append("NOTE: VM obfuscation detected — decompiled VM interpreter (not original source)")
                    else:
                        lines.append("X OUT -> operation failed")
                    return "\n".join(lines)
                if raw[:2] == b"PK":
                    lines.append("NOTE: ZIP magic — use OBB Tools")
                    return "\n".join(lines)
            except Exception as _e:
                lines.append("preflight-skip: %s" % _e)
            dest = out_dir("PAK") / Path(ip).stem
            dest.mkdir(parents=True, exist_ok=True)
            if sid == "pak_list":
                r = core.run_pak_list(ip, dest / "index_list.txt")
                if not r.get("ok"):
                    lines.append("X PAK LIST FAILED: %s" % r.get("error", r))
                    return "\n".join(lines)
                lines.append("entries=%s -> %s" % (r.get("count"), r.get("out")))
                for pth in (r.get("paths") or [])[:40]:
                    lines.append("  " + pth)
                return "\n".join(lines)
            if sid == "pak_info":
                r = core.run_pak_info(ip, dest / "info.txt")
                if not r.get("ok"):
                    lines.append("X PAK INFO FAILED: %s" % r.get("error", r))
                else:
                    lines.append(r.get("info", str(r)))
                return "\n".join(lines)
            if sid == "pak_csv":
                r = core.run_pak_list(ip, None)
                if not r.get("ok"):
                    lines.append("X PAK CSV FAILED: %s" % r.get("error", r))
                    return "\n".join(lines)
                paths = r.get("paths") or []
                csvp = dest / "index.csv"
                csvp.write_text("path\n" + "\n".join(paths), encoding="utf-8")
                lines.append("OK csv=%s n=%s" % (csvp, len(paths)))
                return "\n".join(lines)
            # Start from a clean destination so stale files can never satisfy
            # the extraction verification below.
            try:
                if dest.exists():
                    shutil.rmtree(dest)
                dest.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                lines.append("X PAK UNPACK FAILED: cannot reset output directory: %s" % (str(exc)[:500]))
                return "\n".join(lines)
            try:
                r = core.run_pak_unpack(ip, dest)
            except Exception as exc:
                lines.append("X PAK UNPACK FAILED: %s" % (str(exc)[:1200] or type(exc).__name__))
                return "\n".join(lines)
            if not isinstance(r, dict) or not r.get("ok"):
                lines.append("X PAK UNPACK FAILED: %s" % (
                    r.get("error", r) if isinstance(r, dict) else str(r)
                ))
                return "\n".join(lines)
            files = [p for p in dest.rglob("*") if p.is_file()]
            lua_files = [p for p in files if p.suffix.lower() == ".lua"]
            if not files:
                lines.append("X PAK UNPACK produced zero files; refusing false success")
                lines.append("Check archive format, index encryption, keys, and core-patch compatibility")
                return "\n".join(lines)
            lines.append("OK PAK UNPACK files=%d lua=%d" % (len(files), len(lua_files)))
            lines.append("OUT -> %s" % dest)
            if not lua_files:
                lines.append("NOTE: no .lua files found in extracted output")
            else:
                names = sorted({p.name for p in lua_files})
                names_by_lower = {name.lower(): name for name in names}
                requested_targets = ("BRPlayerCharacterBase.lua", "CharacterBase.lua")
                found_targets = []
                missing_targets = []
                for target in requested_targets:
                    actual = names_by_lower.get(target.lower())
                    if actual:
                        found_targets.append(actual)
                        lines.append("FOUND TARGET LUA -> %s" % actual)
                    else:
                        missing_targets.append(target)
                if missing_targets:
                    lines.append(
                        "NOTE target filename(s) are not present in this PAK index: %s"
                        % ", ".join(missing_targets)
                    )
                lines.append(
                    "Lua filenames sample -> %s"
                    % ", ".join(names[:12])
                )
            return "\n".join(lines)

        # ── 2  PAK Rebuild ───────────────────────────────────────────────
        if mid == 2 or sid in ("pak_repack_full","pak_inject","pak_encrypt","pak_decrypt_restore"):
            if not need_file(): return "\n".join(lines)
            if sid == "pak_encrypt":
                dest = out_dir("PAK") / (Path(ip).stem + "_enc.pak")
                lines.append(str(core.run_file_simple1_crypt(ip, dest, True)))
                return "\n".join(lines)
            if sid == "pak_decrypt_restore":
                dest = out_dir("PAK") / (Path(ip).stem + "_dec.pak")
                lines.append(str(core.run_file_simple1_crypt(ip, dest, False)))
                return "\n".join(lines)
            pak_file = Path(ip)
            mod_dir = next(
                (c for c in (out/"WORK"/"MOD", out/"OUT"/"PAK"/pak_file.stem,
                             pak_file.parent/"Modified_files") if c.is_dir()),
                None,
            )
            if mod_dir is None:
                lines.append("X Put edited files in OUT/PAK/<stem>/ or WORK/MOD then select base .pak")
                return "\n".join(lines)
            dest = out_dir("PAK") / (pak_file.stem + "_repack.pak")
            r = core.run_pak_smart_repack(pak_file, mod_dir, dest)
            if not r.get("ok"):
                r = core.run_pak_repack(pak_file, mod_dir, dest)
            lines.append(str(r))
            return "\n".join(lines)

        # ── 3  PAK Compact ───────────────────────────────────────────────
        if mid == 3 or "delete" in sid:
            if not need_file(): return "\n".join(lines)
            if sid == "pak_delete_all":
                dest = out_dir("PAK") / (Path(ip).stem + "_empty.pak")
                lines.append(str(core.run_pak_delete_all(ip, dest)))
                return "\n".join(lines)
            tfile = out / "WORK" / "delete_targets.txt"
            targets = []
            if tfile.is_file():
                targets = [x.strip() for x in tfile.read_text().splitlines() if x.strip()]
            if not targets:
                lines.append("X Create WORK/delete_targets.txt with one internal path per line")
                return "\n".join(lines)
            dest = out_dir("PAK") / (Path(ip).stem + "_del.pak")
            lines.append(str(core.run_pak_delete_entries(ip, dest, targets)))
            return "\n".join(lines)

        # ── 4  OBB Tools ─────────────────────────────────────────────────
        if mid == 4 or sid.startswith("obb_"):
            if not need_file(): return "\n".join(lines)
            p = Path(ip)
            if sid == "obb_info":
                dest = out_dir("OBB") / "info.txt"
                try:
                    import zipfile
                    size = p.stat().st_size
                    report = ["OBB INFO", f"name={p.name}", f"size={size} bytes"]
                    if p.suffix.lower() in (".obb", ".zip"):
                        with zipfile.ZipFile(p, "r") as z:
                            report.append(f"entries={len(z.infolist())}")
                    dest.write_text("\n".join(report), encoding="utf-8")
                    lines.extend(report)
                    lines.append(f"OK OUT -> {dest}")
                except Exception as e:
                    lines.append(f"X {e}")
                return "\n".join(lines)
            if sid == "obb_unzip":
                d = out_dir("OBB") / p.stem
                r = feat.run_obb_extract(ip, d)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "obb_rezip":
                dest = out_dir("OBB") / (p.stem + "_rezip.obb")
                extracted = out_dir("OBB") / p.stem
                if not extracted.is_dir():
                    lines.append("X Extract this OBB first; expected edited tree at OUT/OBB/%s" % p.stem)
                    return "\n".join(lines)
                r = feat.run_obb_rezip(str(extracted), dest)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 5  LUA Tools ─────────────────────────────────────────────────
        if mid == 5 or sid.startswith("lua_"):
            if sid not in ("lua_decompile",) and not need_file():
                return "\n".join(lines)
            dest_lua = out_dir("LUA")
            if sid == "lua_decompile":
                if not need_file(): return "\n".join(lines)
                # Use the streaming decompiler for large files (>8 MiB) so we
                # never OOM on inputs that the in-process ART unluac rejects.
                try:
                    in_size = Path(ip).stat().st_size
                except Exception:
                    in_size = 0
                if in_size > 8 * 1024 * 1024:
                    try:
                        from lua_engine.streaming_decompiler import decompile_large
                        r = decompile_large(Path(ip), dest_lua, jars_dir=jars)
                        r.setdefault("lines", 0)
                        r.setdefault("mode", "streaming_fallback")
                        if r.get("ok"):
                            lines.append("OK mode=%s lines=%s" % (r.get("mode","?"), r.get("lines",0)))
                            lines.append("OUT -> %s" % r.get("out","(see OUT/LUA/)"))
                            if r.get("note"):
                                lines.append("NOTE: %s" % r.get("note"))
                            if r.get("container"):
                                lines.append("OK container=%s" % r.get("container"))
                            return "\n".join(lines)
                        # fall through to run_lua_smart as second attempt
                        lines.append("... streaming decompiler produced no output, trying run_lua_smart")
                    except Exception as exc:
                        lines.append("... streaming decompiler exception: %s" % exc)
                r = feat.run_lua_smart(ip, dest_lua, jars_dir=jars)
                if r.get("ok"):
                    lines.append("OK mode=%s lines=%s" % (r.get("mode","?"), r.get("lines",0)))
                    lines.append("OUT -> %s" % r.get("out","(see OUT/LUA/)"))
                    vm_notes = r.get("vm_notes") or []
                    if r.get("vm_obfuscated"):
                        lines.append("NOTE: VM obfuscation detected (confidence=%.2f)" % (r.get("vm_confidence",0)))
                        lines.append("NOTE: File uses runtime VM — decompiled VM interpreter (not original source)")
                        for n in (vm_notes[:3] if isinstance(vm_notes, list) else []):
                            lines.append("  · %s" % n)
                    else:
                        lines.append("OK decompile complete")
                else:
                    lines.append("X OUT -> operation failed")
                    for s in (r.get("steps") or [])[-3:]:
                        lines.append("  step=%s ok=%s" % (s.get("step"), s.get("ok")))
                return "\n".join(lines)
            if sid == "lua_analyze":
                r = feat.run_lua_analyze(ip, dest_lua)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_constants":
                r = feat.run_lua_constants(ip, dest_lua)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_clean_source":
                r = feat.run_lua_clean(ip, dest_lua)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_xor_crypt":
                r = feat.run_lua_xor(ip, dest_lua, key_hex=None)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_multi_xor":
                r = feat.run_lua_multi_xor(ip, dest_lua)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_vm_deobfuscate":
                # Module 05 / VM Deobfuscate — auto-detect known protection patterns
                # (ALVSEAL3, ALVLUA1, BGMI-VM, ...) and extract what's recoverable.
                try:
                    from lua_engine.vm_deobfuscator import vm_deobfuscate
                    from lua_engine.pattern_registry import list_patterns
                    r = vm_deobfuscate(Path(ip), dest_lua)
                    patterns = list_patterns()
                    lines.append("ALVSIA VM Deobfuscator — %d patterns registered" % len(patterns))
                    for p in patterns:
                        lines.append("  · %-18s %s" % (p["id"], p["label"]))
                    lines.append("")
                    if r.get("ok"):
                        lines.append("OK pattern matched: %s" % r.get("pattern_id", "?"))
                        lines.append("  label: %s" % r.get("pattern_label", ""))
                        lines.append("  mode:  %s" % r.get("mode", ""))
                        if r.get("recovered"):
                            lines.append("OK source recovered -> %s" % r.get("out", ""))
                            lines.append("  recovered size: %d bytes" % r.get("recovered_size", 0))
                            lines.append("  is_lua_source:    %s" % r.get("is_lua_source", False))
                        else:
                            lines.append("NOTE partial recovery only — see output files")
                            for k in ("structure_out", "constants_out", "report_out"):
                                if r.get(k):
                                    lines.append("  -> %s" % r[k])
                            if r.get("note"):
                                lines.append("NOTE %s" % r["note"])
                    else:
                        lines.append("X deobfuscate failed: %s" % r.get("error", "unknown"))
                        if r.get("note"):
                            lines.append("NOTE %s" % r["note"])
                    lines.append("elapsed_ms=%s" % r.get("elapsed_ms", 0))
                    return "\n".join(lines)
                except Exception as exc:
                    lines.append("X VM deobfuscate exception: %s" % (str(exc)[:400] or type(exc).__name__))
                    import traceback as _tb
                    lines.append(_tb.format_exc()[:1200])
                    return "\n".join(lines)

        # ── 6  File Scan ─────────────────────────────────────────────────
        if mid == 6 or sid in ("string_scan", "hash_scan"):
            if not need_file(): return "\n".join(lines)
            dest_sc = out_dir("SCAN")
            if sid == "string_scan":
                r = feat.run_strings_scan(ip, dest_sc)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "hash_scan":
                # run_hash_file expects an output FILE path (not a directory)
                dest_hash = dest_sc / (Path(ip).stem + "_hash.txt")
                r = feat.run_hash_file(ip, dest_hash)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 7  Workspace ─────────────────────────────────────────────────
        if mid == 7 or sid == "clear_work":
            for d in (out / "WORK", out / "OUT"):
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
                    d.mkdir(parents=True, exist_ok=True)
            lines.append("OK workspace cleared")
            return "\n".join(lines)

        # ── 8  Export Report ─────────────────────────────────────────────
        if mid == 8 or sid == "export_report":
            if not need_file(): return "\n".join(lines)
            r = feat.run_export_report(ip, out_dir("REPORT"))
            lines.append(str(r))
            return "\n".join(lines)

        # ── 9  Rebrand ───────────────────────────────────────────────────
        if mid == 9 or sid.startswith("rebrand_"):
            if not need_file(): return "\n".join(lines)
            cfg_path = str(work_dir() / "rebrand_config.txt")
            if sid == "rebrand_auto":
                r = feat.run_rebrand(ip, out_dir("REBRAND"), cfg_path, auto=True)
            elif sid == "rebrand_manual":
                r = feat.run_rebrand(ip, out_dir("REBRAND"), cfg_path, auto=False)
            elif sid == "rebrand_scan":
                r = feat.run_rebrand_scan(ip, out_dir("REBRAND"))
            else:
                r = {"ok": False, "msg": "unknown rebrand sub"}
            lines.append(str(r))
            return "\n".join(lines)

        # ── 10  SO Analyzer ──────────────────────────────────────────────
        if mid == 10 or sid.startswith("so_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_so = out_dir("SO")
            if sid == "so_xor_scan":
                r = ult.so_xor_brute(ip, dest_so)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "so_multi_xor":
                key_file = work_dir() / "xor_keys.txt"
                keys = [ln.strip().replace(" ", "") for ln in key_file.read_text().splitlines()
                        if ln.strip()] if key_file.is_file() else []
                if not keys:
                    lines.append("X Add one hexadecimal XOR key per line to WORK/xor_keys.txt")
                    return "\n".join(lines)
                results = []
                for index, key_hex in enumerate(keys, 1):
                    result = ult.so_multi_xor(ip, dest_so, key_hex)
                    if result.get("ok") and result.get("out"):
                        generated = Path(result["out"])
                        unique = dest_so / ("so_xored_key%02d_%s" % (index, Path(ip).name))
                        try:
                            generated.replace(unique)
                            result["out"] = str(unique)
                        except Exception:
                            pass
                    results.append(result)
                lines.append(str({"ok": any(x.get("ok") for x in results),
                                  "keys_tried": len(keys), "results": results}))
                return "\n".join(lines)
            if sid == "so_url_dump":
                r = ult.so_url_dump(ip, dest_so)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "so_aes_probe":
                r = ult.so_aes_probe(ip, dest_so)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "so_patch_url":
                cfg = read_config("patch_config.txt")
                old_url, new_url = cfg.get("old_url", ""), cfg.get("new_url", "")
                if not old_url or not new_url:
                    lines.append("X WORK/patch_config.txt must contain old_url=<existing URL> and new_url=<replacement URL>")
                    return "\n".join(lines)
                r = ult.so_patch_url(ip, dest_so, old_url, new_url)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 11  Frida Tracer ─────────────────────────────────────────────
        if mid == 11 or sid.startswith("frida_"):
            import alvsia_ultimate as ult
            dest_fr = out_dir("FRIDA")
            pkg_file = work_dir() / "frida_target.txt"
            pkg = pkg_file.read_text().strip() if pkg_file.exists() else ""
            if sid == "frida_js_dump":
                r = ult.frida_generate_script(pkg or "com.example.app", dest_fr)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "frida_jni_hook":
                if not need_file():
                    return "\n".join(lines)
                r = ult.frida_jni_hook(ip, dest_fr)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "frida_spawn":
                if not pkg:
                    lines.append("X Write target package to WORK/frida_target.txt")
                    return "\n".join(lines)
                r = ult.frida_spawn_trace(pkg, dest_fr)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 12  XOR Suite ────────────────────────────────────────────────
        if mid == 12 or sid.startswith("xor_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_xor = out_dir("XOR")
            if sid == "xor_single_byte":
                r = ult.xor_single_byte_scan(ip, dest_xor)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "xor_custom_key":
                kf = work_dir() / "xor_key.txt"
                if not kf.exists():
                    lines.append("X Put key in WORK/xor_key.txt (hex bytes, e.g. DEADBEEF)")
                    return "\n".join(lines)
                key_hex = kf.read_text(encoding="utf-8").strip()
                r = ult.xor_apply_key(ip, dest_xor, key_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "xor_luas_strip":
                r = ult.xor_luas_strip(ip, dest_xor)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "xor_batch":
                batch_dir = work_dir() / "BATCH"
                kf = work_dir() / "xor_key.txt"
                if not kf.exists() or not batch_dir.exists():
                    lines.append("X Need WORK/BATCH/ dir and WORK/xor_key.txt")
                    return "\n".join(lines)
                key_hex = kf.read_text(encoding="utf-8").strip()
                r = ult.xor_batch(str(batch_dir), dest_xor, key_hex)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 13  Decrypt Engine ───────────────────────────────────────────
        if mid == 13 or sid.startswith("dec_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_dec = out_dir("DEC")
            if sid == "dec_auto":
                r = ult.decrypt_auto(ip, dest_dec)
                lines.append(str(r))
                return "\n".join(lines)
            if sid in ("dec_aes_cbc", "dec_aes_ecb"):
                cfg = read_config("aes_config.txt")
                key_hex = cfg.get("key", cfg.get("key_hex", ""))
                iv_hex = cfg.get("iv", cfg.get("iv_hex", "")) if sid == "dec_aes_cbc" else ""
                if not key_hex or (sid == "dec_aes_cbc" and not iv_hex):
                    lines.append("X WORK/aes_config.txt requires key=<hex>; AES-CBC also requires iv=<hex>")
                    return "\n".join(lines)
                r = ult.decrypt_aes(ip, dest_dec, key_hex, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_zuc":
                cfg = read_config("zuc_config.txt")
                key_hex, iv_hex = cfg.get("key", cfg.get("key_hex", "")), cfg.get("iv", cfg.get("iv_hex", ""))
                if not key_hex:
                    lines.append("X WORK/zuc_config.txt requires key=<hex> (optional iv=<hex>)")
                    return "\n".join(lines)
                r = ult.decrypt_zuc(ip, dest_dec, key_hex, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_sm4":
                cfg = read_config("sm4_config.txt")
                key_hex = cfg.get("key", cfg.get("key_hex", ""))
                mode = cfg.get("mode", "ECB").upper()
                iv_hex = cfg.get("iv", cfg.get("iv_hex", ""))
                if not key_hex:
                    lines.append("X WORK/sm4_config.txt requires key=<32 hex characters>")
                    return "\n".join(lines)
                if mode == "CBC" and not iv_hex:
                    lines.append("X SM4-CBC requires iv=<32 hex characters>")
                    return "\n".join(lines)
                r = ult.decrypt_sm4(ip, dest_dec, key_hex, mode, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_simple1":
                r = ult.decrypt_simple1(ip, dest_dec)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 14  PAK Deep ─────────────────────────────────────────────────
        if mid == 14 or sid.startswith("pak_deep_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_pakd = out_dir("PAKD")
            if sid == "pak_deep_aes":
                cfg = read_config("pak_pass.txt")
                key_hex = cfg.get("key", cfg.get("key_hex", ""))
                iv_hex = cfg.get("iv", cfg.get("iv_hex", ""))
                passphrase = cfg.get("passphrase", "")
                if not passphrase and not key_hex:
                    raw_cfg = (work_dir() / "pak_pass.txt")
                    if raw_cfg.is_file():
                        raw_text = raw_cfg.read_text(encoding="utf-8").strip()
                        if raw_text and "=" not in raw_text:
                            passphrase = raw_text
                if not key_hex and passphrase:
                    key_hex = hashlib.sha1(passphrase.encode("utf-8")).hexdigest()[:32]
                if not key_hex or not iv_hex:
                    lines.append("X WORK/pak_pass.txt requires passphrase=<text> plus iv=<32 hex chars>, or key=<32 hex chars> plus iv=<32 hex chars>")
                    return "\n".join(lines)
                r = ult.pak_deep_aes(ip, dest_pakd, key_hex, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_zstd":
                r = ult.pak_deep_zstd(ip, dest_pakd)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_zuc":
                cfg = read_config("zuc_config.txt")
                key_hex, iv_hex = cfg.get("key", cfg.get("key_hex", "")), cfg.get("iv", cfg.get("iv_hex", ""))
                if not key_hex:
                    lines.append("X WORK/zuc_config.txt requires key=<hex>")
                    return "\n".join(lines)
                r = ult.pak_deep_zuc(ip, dest_pakd, key_hex, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_sm4":
                cfg = read_config("sm4_config.txt")
                key_hex = cfg.get("key", cfg.get("key_hex", ""))
                mode = cfg.get("mode", "ECB").upper()
                iv_hex = cfg.get("iv", cfg.get("iv_hex", ""))
                if not key_hex:
                    lines.append("X WORK/sm4_config.txt requires key=<32 hex characters>")
                    return "\n".join(lines)
                if mode == "CBC" and not iv_hex:
                    lines.append("X SM4-CBC requires iv=<32 hex characters>")
                    return "\n".join(lines)
                r = ult.pak_deep_sm4(ip, dest_pakd, key_hex, mode, iv_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_auto":
                r = ult.pak_deep_auto(ip, dest_pakd)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 15  String Recover ───────────────────────────────────────────
        if mid == 15 or sid.startswith("str_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_str = out_dir("STR")
            if sid == "str_recover":
                r = ult.string_recover(ip, dest_str)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "str_constant_pool":
                r = ult.string_constant_pool(ip, dest_str)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "str_xref":
                cfg = read_config("xref_query.txt")
                query = cfg.get("search", cfg.get("query", ""))
                if not query:
                    lines.append("X Enter search=<text> in WORK/xref_query.txt")
                    return "\n".join(lines)
                r = ult.string_xref(ip, dest_str, query)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 16  Lua Inject ───────────────────────────────────────────────
        if mid == 16 or sid.startswith("lua_patch_") or sid in ("lua_inject_hook","lua_mod_repack"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_inj = out_dir("LINJ")
            wdir = str(work_dir())
            if sid == "lua_patch_byte":
                cfg = read_config("lua_patch.json")
                patch_offset = cfg.get("offset", "")
                patch_hex = cfg.get("patch_hex", cfg.get("bytes", ""))
                if not patch_offset or not patch_hex:
                    lines.append("X WORK/lua_patch.json must contain offset=0x1234 and patch_hex=DEADBEEF")
                    return "\n".join(lines)
                r = ult.lua_patch_bytecode(ip, dest_inj, patch_offset, patch_hex)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_inject_hook":
                hf = work_dir() / "lua_hook.lua"
                if not hf.is_file():
                    lines.append("X Enter hook Lua source in the CONFIG field (saved as WORK/lua_hook.lua)")
                    return "\n".join(lines)
                r = ult.lua_inject_hook(ip, dest_inj, str(hf))
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_mod_repack":
                pak_file = Path(ip)
                mod_dir = next((candidate for candidate in (
                    work_dir() / "MOD", out / "OUT" / "PAK" / pak_file.stem,
                    pak_file.parent / "Modified_files"
                ) if candidate.is_dir()), None)
                if mod_dir is None:
                    lines.append("X Add the modified tree to WORK/MOD or OUT/PAK/<pak-name> before repacking")
                    return "\n".join(lines)
                dest = dest_inj / (pak_file.stem + "_modded.pak")
                result = core.run_pak_smart_repack(pak_file, mod_dir, dest)
                if not result.get("ok"):
                    result = core.run_pak_repack(pak_file, mod_dir, dest)
                lines.append(str(result))
                return "\n".join(lines)

        # ── 17  Anti-RE Audit ────────────────────────────────────────────
        if mid == 17 or sid.startswith("audit_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_audit = out_dir("AUDIT")
            if sid == "audit_apk":
                r = ult.audit_apk(ip, dest_audit)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "audit_lua":
                r = ult.audit_lua(ip, dest_audit)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "audit_so":
                r = ult.audit_so(ip, dest_audit)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 18  Lua Protector (authenticated encrypted package) ───────────
        if mid == 18 or sid in ("lua_protect_encrypt", "lua_protect_decrypt",
                                 "lua_vm_protect"):
            if not need_file():
                return "\n".join(lines)
            dest_dir = out_dir("LPROTECT")

            # ── 18 / VM-protect: BGMI-style self-executing Lua source ────
            if sid == "lua_vm_protect":
                try:
                    from alvsia_vm_protect import vm_protect
                    dest = dest_dir / (Path(ip).stem + ".alvlua3.lua")
                    r = vm_protect(Path(ip), dest, output_format="lua",
                                    num_decoys=1024)
                    if r.get("ok"):
                        lines.append("OK VM-protected Lua payload (BGMI pattern)")
                        lines.append("mode=%s payload=%d bytes decoys=%d" % (
                            r.get("mode"), r.get("payload_size", 0),
                            r.get("decoys", 0)))
                        lines.append("OUT -> %s" % r.get("out"))
                        lines.append("NOTE: self-executing — load() runs the original code")
                        lines.append("NOTE: reversible via module 05 / VM Deobfuscate")
                    else:
                        lines.append("X VM protect failed: %s" % r.get("error"))
                    return "\n".join(lines)
                except Exception as exc:
                    lines.append("X VM protect exception: %s" % (str(exc)[:400] or type(exc).__name__))
                    return "\n".join(lines)

            # ── 18 / AES-GCM encrypt + decrypt (original ALVLUA1 format) ──
            try:
                from Crypto.Cipher import AES
                from Crypto.Random import get_random_bytes
                key_file = work_dir() / "lua_protect_key.txt"
                if not key_file.is_file():
                    lines.append("X Create WORK/lua_protect_key.txt with a 64-character hex key (32 random bytes)")
                    return "\n".join(lines)
                key_hex = key_file.read_text(encoding="utf-8").strip()
                if not re.fullmatch(r"[0-9a-fA-F]{64}", key_hex):
                    lines.append("X Lua Protector key must be exactly 64 hexadecimal characters")
                    return "\n".join(lines)
                key = bytes.fromhex(key_hex)
                source = Path(ip).read_bytes()
                dest_dir = out_dir("LPROTECT")
                if sid == "lua_protect_encrypt":
                    nonce = get_random_bytes(12)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
                    cipher.update(b"ALVLUA1")
                    ciphertext, tag = cipher.encrypt_and_digest(source)
                    dest = dest_dir / (Path(ip).stem + ".alvlua")
                    dest.write_bytes(b"ALVLUA1" + nonce + tag + ciphertext)
                    lines.append("OK encrypted + authenticated Lua payload")
                    lines.append("NOTE keep the 32-byte key private; it is not embedded in the output")
                elif sid == "lua_protect_decrypt":
                    if len(source) < 35 or source[:7] != b"ALVLUA1":
                        lines.append("X Invalid ALVLUA1 header or truncated payload")
                        return "\n".join(lines)
                    nonce, tag, ciphertext = source[7:19], source[19:35], source[35:]
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
                    cipher.update(b"ALVLUA1")
                    try:
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    except ValueError:
                        lines.append("X Authentication failed: wrong key or modified payload")
                        return "\n".join(lines)
                    dest = dest_dir / (Path(ip).stem + ".lua")
                    dest.write_bytes(plaintext)
                    lines.append("OK authentication passed; Lua source restored")
                else:
                    lines.append("X Unknown Lua Protector operation")
                    return "\n".join(lines)
                lines.append("OUT -> %s" % dest)
                return "\n".join(lines)
            except ImportError:
                lines.append("X PyCryptodome AES module unavailable in this runtime")
                return "\n".join(lines)
            except Exception as exc:
                lines.append("X Lua Protector failed: %s" % (str(exc)[:400] or type(exc).__name__))
                return "\n".join(lines)

        # ── fallback ─────────────────────────────────────────────────────
        lines.append("X Unknown sub_id='%s' for module=%s" % (sid, mid))
        return "\n".join(lines)

    except Exception as exc:
        lines.append("X BRIDGE EXCEPTION: %s" % exc)
        lines.append(traceback.format_exc())
        return "\n".join(lines)


def bridge_run_sub(module_id, sub_id, input_path, extra_name, work_dir_path, jars_dir_path):
    """Entry point called by PythonBridgeRunner.runBridge() via reflection."""
    return run_tool(
        module_id=int(module_id),
        sub_id=str(sub_id),
        input_path=str(input_path) if input_path else "",
        out_root=str(work_dir_path),
        engine_dir=str(jars_dir_path),
        jars_dir=str(jars_dir_path),
    )

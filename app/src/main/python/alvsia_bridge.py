# -*- coding: utf-8 -*-
"""
ALVSIA PRO 5.5.0 — bridge for 17-module catalog.
Modules 1-9: original. Modules 10-17: new in v5.5.0.
"""
from __future__ import annotations
import os
import shutil
import traceback
from pathlib import Path

# SECURITY: do NOT hardcode ALVSIA_APK_SESSION / ALVSIA_SOFT_AUTH here.
# Kotlin sets ALVSIA_APK_SESSION=1 only AFTER successful OTP + SessionGate.sessionOk.

def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    lines = []
    try:
        # Hard gate
        if os.environ.get("ALVSIA_APK_SESSION") != "1" and os.environ.get("ALVSIA_SOFT_AUTH") != "1":
            return "X AUTH: no valid APK session — complete license + OTP first"
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
                    lines.append(str(feat.run_lua_smart(ip, dest, jars_dir=jars)))
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
                lines.append("entries=%s -> %s" % (r.get("count"), r.get("out")))
                for pth in (r.get("paths") or [])[:40]:
                    lines.append("  " + pth)
                return "\n".join(lines)
            if sid == "pak_info":
                r = core.run_pak_info(ip, dest / "info.txt")
                lines.append(r.get("info", str(r)))
                return "\n".join(lines)
            if sid == "pak_csv":
                r = core.run_pak_list(ip, None)
                paths = r.get("paths") or []
                csvp = dest / "index.csv"
                csvp.write_text("path\n" + "\n".join(paths), encoding="utf-8")
                lines.append("OK csv=%s n=%s" % (csvp, len(paths)))
                return "\n".join(lines)
            r = core.run_pak_unpack(ip, dest)
            lines.append(str(r))
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
                r = feat.run_obb_rezip(ip, dest)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 5  LUA Tools ─────────────────────────────────────────────────
        if mid == 5 or sid.startswith("lua_"):
            if sid not in ("lua_decompile",) and not need_file():
                return "\n".join(lines)
            dest_lua = out_dir("LUA")
            if sid == "lua_decompile":
                if not need_file(): return "\n".join(lines)
                r = feat.run_lua_smart(ip, dest_lua, jars_dir=jars)
                lines.append(str(r))
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
                r = feat.run_lua_xor(ip, dest_lua, key_byte=None)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_multi_xor":
                r = feat.run_lua_multi_xor(ip, dest_lua)
                lines.append(str(r))
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
                r = feat.run_hash_file(ip, dest_sc)
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
                keys = []
                if key_file.exists():
                    for ln in key_file.read_text().splitlines():
                        ln = ln.strip()
                        if ln:
                            try:
                                keys.append(bytes.fromhex(ln))
                            except Exception:
                                keys.append(ln.encode("utf-8"))
                r = ult.so_multi_xor(ip, dest_so, custom_keys=keys)
                lines.append(str(r))
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
                cfg = work_dir() / "patch_config.txt"
                if not cfg.exists():
                    lines.append("X Create WORK/patch_config.txt: offset=0x... key=0x.. new_url=https://...")
                    return "\n".join(lines)
                r = ult.so_patch_url(ip, dest_so, str(cfg))
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
                if not pkg:
                    lines.append("X Write target package to WORK/frida_target.txt")
                    return "\n".join(lines)
                r = ult.frida_jni_hook(pkg, dest_fr)
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
                key = bytes.fromhex(kf.read_text().strip())
                r = ult.xor_apply_key(ip, dest_xor, key)
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
                key = bytes.fromhex(kf.read_text().strip())
                r = ult.xor_batch(str(batch_dir), dest_xor, key)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 13  Decrypt Engine ───────────────────────────────────────────
        if mid == 13 or sid.startswith("dec_"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_dec = out_dir("DEC")
            if sid == "dec_auto":
                r = ult.decrypt_auto(ip, dest_dec, str(work_dir()))
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_aes_cbc":
                r = ult.decrypt_aes(ip, dest_dec, str(work_dir()), mode="CBC")
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_aes_ecb":
                r = ult.decrypt_aes(ip, dest_dec, str(work_dir()), mode="ECB")
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_zuc":
                r = ult.decrypt_zuc(ip, dest_dec, str(work_dir()))
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "dec_sm4":
                r = ult.decrypt_sm4(ip, dest_dec, str(work_dir()))
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
            wdir = str(work_dir())
            if sid == "pak_deep_aes":
                r = ult.pak_deep_aes(ip, dest_pakd, wdir)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_zstd":
                r = ult.pak_deep_zstd(ip, dest_pakd)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_zuc":
                r = ult.pak_deep_zuc(ip, dest_pakd, wdir)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_sm4":
                r = ult.pak_deep_sm4(ip, dest_pakd, wdir)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "pak_deep_auto":
                r = ult.pak_deep_auto(ip, dest_pakd, wdir)
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
                r = ult.string_xref(ip, dest_str)
                lines.append(str(r))
                return "\n".join(lines)

        # ── 16  Lua Inject ───────────────────────────────────────────────
        if mid == 16 or sid.startswith("lua_patch_") or sid in ("lua_inject_hook","lua_mod_repack"):
            import alvsia_ultimate as ult
            if not need_file(): return "\n".join(lines)
            dest_inj = out_dir("LINJ")
            wdir = str(work_dir())
            if sid == "lua_patch_byte":
                pf = work_dir() / "lua_patch.json"
                if not pf.exists():
                    lines.append("X Create WORK/lua_patch.json: {\"offset\":N, \"opcode\":N, \"value\":N}")
                    return "\n".join(lines)
                r = ult.lua_patch_bytecode(ip, dest_inj, str(pf))
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_inject_hook":
                hf = work_dir() / "lua_hook.lua"
                if not hf.exists():
                    lines.append("X Create WORK/lua_hook.lua with your hook code")
                    return "\n".join(lines)
                r = ult.lua_inject_hook(ip, dest_inj, str(hf), jars_dir=jars)
                lines.append(str(r))
                return "\n".join(lines)
            if sid == "lua_mod_repack":
                r = ult.lua_mod_repack(ip, dest_inj, wdir, jars_dir=jars)
                lines.append(str(r))
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

        # ── fallback ─────────────────────────────────────────────────────
        lines.append("X Unknown sub_id='%s' for module=%s" % (sid, mid))
        return "\n".join(lines)

    except Exception as exc:
        lines.append("X BRIDGE EXCEPTION: %s" % exc)
        lines.append(traceback.format_exc())
        return "\n".join(lines)

# -*- coding: utf-8 -*-
"""ALVSIA PRO 4.6 — bridge for 9-module catalog (incl. Rebrand)."""
from __future__ import annotations
import os
import shutil
import traceback
from pathlib import Path

os.environ["ALVSIA_APK_SESSION"] = "1"
os.environ.setdefault("ALVSIA_SOFT_AUTH", "1")


def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    lines = []
    try:
        lines.append("ALVSIA PRO 4.6 PREMIUM · engine")
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

        # --- 1 PAK Unpack ---
        if mid == 1 or sid.startswith("pak_full") or sid in ("pak_list", "pak_info", "pak_csv"):
            if not need_file():
                return "\n".join(lines)
            # Auto-detect: some VIP packs rename LuaS bytecode as .pak
            try:
                head = Path(ip).read_bytes()[:8]
                if head[:4] == b"\x1bLua":
                    lines.append("NOTE: file is LuaS bytecode (not PAK) — routing to LUA smart pipeline")
                    dest = out / "OUT" / "LUA"
                    lines.append(str(feat.run_lua_smart(ip, dest, jars_dir=jars)))
                    return "\n".join(lines)
            except Exception as _e:
                lines.append("detect-skip: %s" % _e)
            dest = out / "OUT" / "PAK" / Path(ip).stem
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

        # --- 2 PAK Rebuild ---
        if mid == 2 or sid in ("pak_repack_full", "pak_inject", "pak_encrypt", "pak_decrypt_restore"):
            if not need_file():
                return "\n".join(lines)
            if sid == "pak_encrypt":
                dest = out / "OUT" / "PAK" / (Path(ip).stem + "_enc.pak")
                lines.append(str(core.run_file_simple1_crypt(ip, dest, True)))
                return "\n".join(lines)
            if sid == "pak_decrypt_restore":
                dest = out / "OUT" / "PAK" / (Path(ip).stem + "_dec.pak")
                lines.append(str(core.run_file_simple1_crypt(ip, dest, False)))
                return "\n".join(lines)
            pak_file = Path(ip)
            mod_dir = next(
                (
                    c
                    for c in (
                        out / "WORK" / "MOD",
                        out / "OUT" / "PAK" / pak_file.stem,
                        pak_file.parent / "Modified_files",
                    )
                    if c.is_dir()
                ),
                None,
            )
            if mod_dir is None:
                lines.append("X Put edited files in OUT/PAK/<stem>/ or WORK/MOD then select base .pak")
                return "\n".join(lines)
            dest = out / "OUT" / "PAK" / (pak_file.stem + "_repack.pak")
            r = core.run_pak_smart_repack(pak_file, mod_dir, dest)
            if not r.get("ok"):
                r = core.run_pak_repack(pak_file, mod_dir, dest)
            lines.append(str(r))
            return "\n".join(lines)

        # --- 3 Compact ---
        if mid == 3 or "delete" in sid:
            if not need_file():
                return "\n".join(lines)
            if sid == "pak_delete_all":
                dest = out / "OUT" / "PAK" / (Path(ip).stem + "_empty.pak")
                lines.append(str(core.run_pak_delete_all(ip, dest)))
                return "\n".join(lines)
            tfile = out / "WORK" / "delete_targets.txt"
            targets = []
            if tfile.is_file():
                targets = [x.strip() for x in tfile.read_text().splitlines() if x.strip()]
            if not targets:
                lines.append("X Create WORK/delete_targets.txt with one internal path per line")
                return "\n".join(lines)
            dest = out / "OUT" / "PAK" / (Path(ip).stem + "_del.pak")
            lines.append(str(core.run_pak_delete_entries(ip, dest, targets)))
            return "\n".join(lines)

        # --- 4 OBB ---
        if mid == 4 or sid.startswith("obb_"):
            if not need_file():
                return "\n".join(lines)
            p = Path(ip)
            if sid == "obb_rezip":
                tree = out / "OUT" / "OBB" / p.stem
                if not tree.is_dir():
                    tree = p if p.is_dir() else p.parent / p.stem
                if not tree.is_dir():
                    lines.append("X unpacked folder not found")
                    return "\n".join(lines)
                dest = out / "OUT" / "OBB" / (tree.name + "_repack.obb")
                lines.append(str(feat.run_zip_tree(tree, dest)))
                return "\n".join(lines)
            dest = out / "OUT" / "OBB" / p.stem
            if p.suffix.lower() in (".zip", ".obb"):
                lines.append(str(feat.run_unzip(p, dest)))
            else:
                lines.append(str(core.run_pak_unpack(ip, dest)))
            return "\n".join(lines)

        # --- 5 LUA ---
        if mid == 5 or sid.startswith("lua_"):
            if not need_file():
                return "\n".join(lines)
            dest = out / "OUT" / "LUA"
            if sid == "lua_xor_crypt":
                lines.append(str(feat.run_lua_xor(ip, dest)))
            elif sid in ("lua_smart", "lua_constants", "lua_multi_xor"):
                if sid == "lua_constants":
                    lines.append(str(feat.extract_lua_constants(ip, dest)))
                elif sid == "lua_multi_xor":
                    lines.append(str(feat.run_lua_multi_xor(ip, dest)))
                else:
                    lines.append(str(feat.run_lua_smart(ip, dest, jars_dir=jars)))
            else:
                # default: full smart pipeline (unluac → constants → strings → multi-xor)
                r = feat.run_lua_smart(ip, dest, jars_dir=jars)
                lines.append(str(r))
            return "\n".join(lines)

        # --- 6 Scan ---
        if mid == 6 or "string" in sid or "hash" in sid:
            if not need_file():
                return "\n".join(lines)
            if "hash" in sid:
                dest = out / "OUT" / "SCAN" / "hash.txt"
                dest.parent.mkdir(parents=True, exist_ok=True)
                r = feat.run_hash_file(ip, dest)
                lines.append(r.get("report", str(r)))
            else:
                dest = out / "OUT" / "SCAN" / "strings.txt"
                dest.parent.mkdir(parents=True, exist_ok=True)
                lines.append(str(feat.run_string_scan(ip, dest)))
            return "\n".join(lines)

        # --- 7 Clear ---
        if mid == 7 or "clear" in sid:
            for sub in ("WORK", "OUT"):
                lines.append("%s %s" % (sub, core.run_clear_tree(out / sub)))
            return "\n".join(lines)

        # --- 8 Report ---
        if mid == 8 or "report" in sid or "export" in sid:
            if need_file():
                dest = out / "OUT" / "REPORT" / "report.txt"
                dest.parent.mkdir(parents=True, exist_ok=True)
                if Path(ip).suffix.lower() in (".pak", ".obb"):
                    lines.append(str(core.run_pak_info(ip, dest)))
                else:
                    lines.append(str(feat.run_hash_file(ip, dest)))
            return "\n".join(lines)

        # --- 9 Rebrand (string only — no bot / no phone-home) ---
        if mid == 9 or sid.startswith("rebrand_"):
            dest = out / "OUT" / "REBRAND"
            dest.mkdir(parents=True, exist_ok=True)
            # ensure config template exists for manual mode
            cfg_path = out / "WORK" / "rebrand_config.txt"
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            if not cfg_path.is_file():
                cfg_path.write_text(
                    "# ALVSIA Rebrand config (manual mode)\n"
                    "# brand=ALVSIA PRO\n"
                    "# channel=t.me/ALVSIA_PRO\n"
                    "# watermark=ALVSIA PRO | t.me/ALVSIA_PRO\n"
                    "brand=ALVSIA PRO\n"
                    "channel=t.me/ALVSIA_PRO\n"
                    "watermark=ALVSIA PRO | t.me/ALVSIA_PRO\n",
                    encoding="utf-8",
                )
            if sid == "rebrand_scan":
                if not need_file():
                    return "\n".join(lines)
                scan_out = dest / "scan.txt"
                r = feat.run_rebrand_scan(ip, scan_out)
                lines.append(r.get("report", str(r)))
                return "\n".join(lines)
            if not need_file():
                return "\n".join(lines)
            p = Path(ip)
            # if user selected a .pak, prefer already-unpacked tree under OUT/PAK/<stem>
            target = p
            if p.suffix.lower() == ".pak":
                unpacked = out / "OUT" / "PAK" / p.stem
                if unpacked.is_dir():
                    target = unpacked
                    lines.append("using unpacked tree: %s" % unpacked)
                else:
                    lines.append("NOTE: select unpacked folder or .lua for best results; .pak binary limited")
            if sid == "rebrand_manual":
                lines.append("config=%s" % cfg_path)
                if target.is_dir():
                    lines.append(str(feat.run_rebrand_tree(target, dest / target.name, out_root=out)))
                else:
                    lines.append(str(feat.run_rebrand_file(target, dest, out_root=out)))
            else:
                # rebrand_auto default
                if target.is_dir():
                    lines.append(str(feat.run_rebrand_tree(target, dest / target.name, out_root=out)))
                else:
                    lines.append(str(feat.run_rebrand_auto(target, dest, out_root=out)))
            lines.append("NOTE: string rebrand only — no Telegram bot inject")
            return "\n".join(lines)

        lines.append("X unhandled m=%s sub=%s" % (mid, sid))
        return "\n".join(lines)
    except Exception as e:
        lines.append("X FATAL: %s" % e)
        lines.append(traceback.format_exc())
        return "\n".join(lines)

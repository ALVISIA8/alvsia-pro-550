#!/usr/bin/env python3
"""Audit the actual ALVISIA release APK for sealed Python/JAR payloads and metadata."""
from __future__ import annotations
import hashlib
import io
import re
import sys
import zipfile
from pathlib import Path

EXPECTED_SEALED = {
    "alvsia_bridge_impl.alv",
    "alvsia_private.alv",
    "alvsia_vm_protect.alv",
    "lua_engine_pattern_registry.alv",
    "alvsia_core.alv",
    "alvsia_ultimate.alv",
    "alvsia_ultimate_compat.alv",
    "alvsia_features.alv",
    "pinned_http.alv",
    "lua_engine_lua_decompiler_final.alv",
    "lua_engine_lua_protector.alv",
    "lua_output_validator.alv",
    "lua_string_recover.alv",
    "lua_engine_engine.alv",
    "lua_engine_decompiler53.alv",
    "lua_engine_bgmi.alv",
    "lua_engine_luajit_decompiler.alv",
    "lua_engine_container.alv",
    "lua_engine_detector.alv",
    "lua_engine_multi_format.alv",
    "lua_engine_streaming_decompiler.alv",
    "lua_engine_vm_deobfuscator.alv",
}
PROTECTED_MODULES = {
    "alvsia_bridge_impl", "alvsia_private", "alvsia_vm_protect", "alvsia_core", "alvsia_ultimate", "alvsia_ultimate_compat",
    "alvsia_features", "pinned_http", "lua_engine/lua_decompiler_final",
    "lua_engine/lua_protector", "lua_engine/pattern_registry",
    "lua_output_validator", "lua_string_recover",
    "lua_engine/engine", "lua_engine/decompiler53", "lua_engine/bgmi",
    "lua_engine/luajit_decompiler", "lua_engine/container", "lua_engine/detector",
    "lua_engine/multi_format", "lua_engine/streaming_decompiler", "lua_engine/vm_deobfuscator",
}
SEAL_MAGIC = b"ALVSEAL2"
ASSET_MAGIC = b"ALVSA1\x00"

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: audit_release_apk.py <release.apk>", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"FAIL APK not found: {apk}", file=sys.stderr)
        return 2
    report, failures = [], []
    def check(ok: bool, msg: str) -> None:
        report.append(("PASS " if ok else "FAIL ") + msg)
        if not ok:
            failures.append(msg)
    data = apk.read_bytes()
    report += [f"APK={apk}", f"SIZE={len(data)}", f"SHA256={hashlib.sha256(data).hexdigest()}"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            check(outer.testzip() is None, "APK ZIP integrity")
            names = set(outer.namelist())
            # The origin must not be recoverable by a simple plaintext scan of packaged files.
            # This is a regression check, not a claim that runtime traffic is secret.
            panel_host_marker = b"alvsiapanel.unaux.com"
            plaintext_host_entries = []
            for entry_name in sorted(names):
                try:
                    entry_bytes = outer.read(entry_name)
                except Exception:
                    continue
                if panel_host_marker in entry_bytes:
                    plaintext_host_entries.append(entry_name)
            check(not plaintext_host_entries,
                  "panel hostname absent from plaintext APK entries" if not plaintext_host_entries
                  else "panel hostname found in plaintext APK entries: " + ", ".join(plaintext_host_entries))
            forbidden_package_names = {"rebrand_config.txt", "app-metadata.properties"}
            packaged_forbidden = sorted(n for n in names if Path(n).name.lower() in forbidden_package_names)
            check(not packaged_forbidden,
                  "sensitive local rebrand/build metadata absent from APK" if not packaged_forbidden
                  else "forbidden APK metadata entries: " + ", ".join(packaged_forbidden))
            check("lib/arm64-v8a/librasp_guard.so" in names, "native RASP library packaged")
            check("assets/chaquopy/app.imy" in names, "Chaquopy app bundle packaged")
            check("assets/nx/i.dat" in names, "sealed JAR index packaged")
            check(not any(n.startswith("assets/unluac/") and n.lower().endswith(".jar") for n in names),
                  "plaintext unluac JAR assets absent")
            vcs_entries = sorted(n for n in names if n.endswith("version-control-info.textproto"))
            check(not vcs_entries, "VCS revision metadata absent" if not vcs_entries else "VCS revision metadata absent; found: " + ", ".join(vcs_entries))
            dex_names = sorted(n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n))
            dex_bytes = b"".join(outer.read(n) for n in dex_names)
            check(b"ALVISIA-20261010-MAIN-SEAL1" not in dex_bytes,
                  "sealed build ID absent from plaintext DEX")
            check(b"com/securevale/" not in dex_bytes,
                  "recognizable SecureVale SDK classes absent from DEX")
            manifest = outer.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
            check(bool(manifest), "compiled Android manifest exists")
            # Resource shrinking may rename compiled res/ paths; verify packaged MP3 payloads.
            audio_entries = sorted(
                n for n in names
                if n.startswith("res/") and n.lower().endswith(".mp3")
            )
            named_background = [n for n in audio_entries if n.lower().endswith("/bgm_pulse.mp3")]
            audio_present = bool(named_background) or len(audio_entries) >= 2
            check(audio_present, "background audio resource packaged" if audio_present else "background audio resource missing from APK")
            for audio_name in audio_entries:
                check(outer.getinfo(audio_name).file_size > 0, f"non-empty media asset: {audio_name}")
            check(b"android.permission.DUMP" not in manifest,
                  "compiled manifest excludes android.permission.DUMP")
            check(b"android.permission.DELETE_PACKAGES" not in manifest,
                  "compiled manifest excludes unused DELETE_PACKAGES")
            check(b"android.permission.CHANGE_NETWORK_STATE" not in manifest,
                  "compiled manifest excludes unused CHANGE_NETWORK_STATE")
            # READ_PHONE_STATE is currently declared for legacy device/tool compatibility.
            # Do not fail the release audit merely because that declared permission is present;
            # any future permission removal must be verified against PermissionHelper/tool usage.
            report.append("INFO compiled manifest READ_PHONE_STATE presence recorded; permission policy is source-reviewed")
            blobs = sorted(n for n in names if n.startswith("assets/nx/") and n.endswith(".bin"))
            check(len(blobs) >= 3, f"sealed JAR asset count >= 3 (found {len(blobs)})")
            for n in blobs:
                check(outer.read(n).startswith(ASSET_MAGIC), f"sealed JAR header: {n}")
            index = outer.read("assets/nx/i.dat") if "assets/nx/i.dat" in names else b""
            check(index.startswith(ASSET_MAGIC), "sealed JAR index header")
            imy = outer.read("assets/chaquopy/app.imy") if "assets/chaquopy/app.imy" in names else b""
            try:
                with zipfile.ZipFile(io.BytesIO(imy)) as inner:
                    check(inner.testzip() is None, "Chaquopy app.imy ZIP integrity")
                    check(not any("version-control-info.textproto" in n for n in inner.namelist()), "VCS metadata absent from Chaquopy bundle")
                    members = inner.namelist()
                    forbidden_inner = sorted(n for n in members if Path(n).name.lower() in forbidden_package_names)
                    check(not forbidden_inner,
                          "sensitive local rebrand/build metadata absent from app.imy" if not forbidden_inner
                          else "forbidden app.imy metadata entries: " + ", ".join(forbidden_inner))
                    # These implementation markers must not be exposed in plaintext
                    # DEX or Python source. Encrypted .alv payloads are deliberately
                    # excluded from this static-string check.
                    plain_python = b"\\n".join(
                        inner.read(n) for n in members if n.lower().endswith(".py")
                    )
                    protected_markers = (b"Feistel-like", b"vm_extract_payload")
                    exposed = [marker.decode("ascii") for marker in protected_markers
                               if marker in dex_bytes or marker in plain_python]
                    check(not exposed,
                          "custom cipher/deobfuscator markers absent from plaintext code" if not exposed
                          else "plaintext protection markers exposed: " + ", ".join(exposed))
                    by_base = {Path(n).name: n for n in members}
                    bridge_name = by_base.get("alvsia_bridge.py")
                    bridge_bytes = inner.read(bridge_name) if bridge_name else b""
                    check(bool(bridge_bytes) and len(bridge_bytes) < 2000,
                          "plaintext bridge is a small bootstrap stub")
                    check(b"import alvsia_bridge_impl as impl" in bridge_bytes and b"if mid == 1" not in bridge_bytes,
                          "tool routing is not shipped in plaintext bridge")
                    actual_sealed = {Path(n).name for n in members if n.lower().endswith(".alv")}
                    missing = sorted(EXPECTED_SEALED - actual_sealed)
                    unexpected = sorted(actual_sealed - EXPECTED_SEALED)
                    check(not missing and not unexpected, "all protected Python payloads exist" if not missing else "missing sealed payloads: " + ", ".join(missing))
                    check(not unexpected, "no unreviewed sealed payloads" if not unexpected else "unexpected sealed payloads: " + ", ".join(unexpected))
                    for name in sorted(EXPECTED_SEALED & actual_sealed):
                        check(inner.read(by_base[name]).startswith(SEAL_MAGIC), f"AES-GCM payload header: {name}")
                    plaintext = []
                    for name in members:
                        normalized = name.replace("\\", "/").lower().lstrip("./")
                        base = Path(normalized).name
                        for module in PROTECTED_MODULES:
                            module = module.lower()
                            parent, _, leaf = module.rpartition("/")
                            source_match = (
                                base == leaf + ".py"
                                or base == leaf + ".pyc"
                                or re.fullmatch(re.escape(leaf) + r"\.[a-z0-9_-]+\.pyc", base) is not None
                            )
                            parent_match = not parent or ("/" + parent + "/") in ("/" + normalized + "/")
                            if source_match and parent_match:
                                plaintext.append(name)
                                break
                    check(not plaintext, "protected Python source/bytecode absent as plaintext" if not plaintext else "plaintext protected modules: " + ", ".join(plaintext))
                    check(any(Path(n).name in {"sealed_loader.py", "sealed_loader.pyc"} for n in members),
                          "sealed Python loader packaged")
            except (zipfile.BadZipFile, OSError) as exc:
                check(False, f"Chaquopy app.imy unreadable: {exc}")
    except (zipfile.BadZipFile, OSError) as exc:
        check(False, f"APK archive unreadable: {exc}")
    report.append("RESULT=" + ("FAIL" if failures else "PASS"))
    text = "\n".join(report) + "\n"
    print(text, end="")
    Path("release_security_audit.txt").write_text(text, encoding="utf-8")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())

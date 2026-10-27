# GRW Tool Source Review — 2026-10-27

## Scope

Reviewed the two uploaded source files in ALVISIA8/kumpulan-source-tool:

- source-tools/GRW/GRW TOOL.py — 4,637 lines (~323 KB)
- source-tools/GRW/GRWTOOL_no_login.py — 4,245 lines (~307 KB)

They are not two independent engines. Both contain substantially duplicated Lua/PAK implementations; the second changes/removes the panel license gate and must not be used as a way to bypass ALVSIA PRO authentication.

## Feature overlap with ALVSIA PRO

The current ALVSIA PRO source already implements most of the valuable core capabilities seen in GRW:

- Lua bytecode parsing, string/number constant extraction and Lua 5.3 decompilation fallbacks.
- BGMI/PUBG scrambled Lua to standard Lua conversion, plus a separate HePing conversion.
- Tencent-style PAK parsing, SM4 and ZUC routines, Zstandard decompression and PAK manifest output.
- PAK unpack/repack helpers, file/string/hash scans, entropy analysis, XOR key recovery, APK auditing and target-size compression search.
- A dedicated sealed-runtime ALVSIA PRIVATE TOOL module, with a test asserting that each private submenu is registered in the bridge.

Relevant existing code is in app/src/main/python/alvsia_core.py, alvsia_features.py, alvsia_private.py, alvsia_bridge_impl.py, and app/src/main/java/com/alvsia/pro/tool/SubMenus.kt. Importing the complete GRW scripts would duplicate hundreds of kilobytes of logic and increase regression risk without adding most of their advertised features.

## Candidate feature that appears to be missing

**Standard Lua 5.3 bytecode → BGMI/PUBG bytecode conversion**, including preserving the original game-specific header/nibble flag and optional padding to an original file size.

The GRW script exposes this through std_to_bgmi() and repack_to_pubg(). The ALVSIA private module currently exposes BGMI → standard and HePing → standard conversions, but does not expose an equivalent reverse-conversion submenu. This is the strongest candidate for a future addition.

Do not port it directly yet: the GRW implementation has no demonstrated round-trip fixture in the uploaded files, and its fallback can copy an input unchanged after conversion errors. Before integrating, add known-good standard/BGMI sample fixtures, strict Lua-header/length checks, conversion round-trip tests, output-size checks, and explicit failure reporting. Never report success merely because an output file was written.

## Do not import as-is

- GRWTOOL_no_login.py removes the panel license gate. Do not use this variant in ALVSIA PRO or weaken the existing key-only login/session checks.
- Both scripts attempt runtime package installation with os.system('pip install ...'). Android app code should use declared/build-time dependencies instead of installing packages during a tool run.
- The scripts contain a Termux self-termination action using pkill -9 -f com.termux. This must not be brought into the app.
- The GRW code contains device-ID collection and sends a license request to its own external panel endpoint. Do not reuse that endpoint or telemetry; retain ALVSIA PRO's current panel/session contract.
- The Lua string obfuscator uses a reversible position-based XOR transformation. It is not a replacement for the existing authenticated AES-GCM Lua Protector.

## Status and next engineering step

- Source files are uploaded and available in this repository.
- Static source comparison is complete; no GRW source was copied into the app.
- The highest-value next implementation is an opt-in reverse BGMI/PUBG Lua conversion under module 19, guarded by fixtures and tests before it is wired into the sealed bridge.
- Keep the existing 19-module catalog, permission declarations, current panel host, and sealed-runtime gate unchanged during that work.
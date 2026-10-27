# ALVSIA PREMIUM TOOL 5.5.2

> **Channel**: [t.me/ALVSIA_PRO](https://t.me/ALVSIA_PRO)  
> **Owner / Developer**: [@OriginalOnwerALV](https://t.me/OriginalOnwerALV)

---

## Overview

ALVSIA PRO is a hardened Android toolkit for PAK/OBB/Lua file analysis and manipulation. It ships with a layered RASP security stack, AES-256-GCM session encryption backed by Android Keystore TEE, TLS 1.3 certificate pinning, and a full **19-module** tool catalog including VM-style Lua protection + deobfuscation.

## Build — CodeMagic

Set the following environment variables in CodeMagic before triggering a build:

| Variable | Description |
|---|---|
| `ALVSIA_SEAL_SEED_HEX` | 64-char hex seal seed (from owner) |
| `ALVSIA_KEYSTORE_PASSWORD` | Keystore password |
| `ALVSIA_KEY_ALIAS` | Key alias |
| `ALVSIA_KEY_PASSWORD` | Key password |

Build command (CodeMagic `scripts` step):
```bash
./gradlew assembleRelease
```

## Build — Termux (manual push & sign)

```bash
# 1. Push to GitHub
cd <project-root>
git init
git remote add origin https://github.com/<user>/<repo>.git
git add .
git commit -m "ALVSIA PRO 5.5.0 R5_4_HARDENED"
git push -u origin main

# 2. Sign locally (if keystore available)
bash RELEASE_SIGN_TERMUX.sh
```

## Module Catalog

| # | Module | Function |
|---|---|---|
| 01 | PAK Unpack | Extract · list · info · CSV |
| 02 | PAK Rebuild | Repack · inject · encrypt · decrypt |
| 03 | PAK Compact | Delete entry · empty · clean |
| 04 | OBB Tools | Unzip · rezip · info |
| 05 | LUA Tools | Detect · analyze · decompile · clean · XOR |
| 06 | File Scan | Strings · MD5/SHA-1/SHA-256 |
| 07 | Workspace | Clear WORK/OUT tree |
| 08 | Export Report | Session / file summary |
| 09 | Rebrand | Auto brand/channel injection |
| 10 | SO Analyzer | XOR-brute 256 keys · URL extract · AES probe · binary patch |
| 11 | Frida Tracer | Live JNI hook · JS script export · spawn+trace |
| 12 | XOR Suite | Single-byte scan · custom key · LuaS strip · batch |
| 13 | Decrypt Engine | AES-CBC/ECB · ZUC · SM4 · SIMPLE1 · auto-detect |
| 14 | PAK Deep | AES-SHA1 · Zstd · ZUC · SM4 · deep auto-probe |
| 15 | String Recover | Obfuscated string restore · constant pool dump · XRef |
| 16 | Lua Inject | Patch bytecode · inject hook function · mod repack |
| 17 | Anti-RE Audit | APK · LUA · SO posture analysis report |
| 18 | Lua Protector | AES-256-GCM encrypt · VM-style BGMI-pattern protect · VM deobfuscate |
| 19 | ALVSIA PRIVATE TOOL | Private analysis suite · sealed runtime required |

## Security Architecture

- **RASP Engine** — 8-second tick · deep scan 60s · hard-kill on instrumentation
- **Session Gate** — AES-256-GCM · Android Keystore TEE · 12h TTL · HMAC-tagged strike counter
- **Native Guard** — `librasp_guard.so` · 8-flag bitmask (TracerPid/maps/ptrace/hwbp/hook/cap/hash/timing)
- **TLS Pinning** — SPKI SHA-256 pin · blocks MITM in release builds
- **Integrity Bomb** — cert SHA-256 · DEX count · clone container check
- **Frida Probe** — `/proc/maps` · port 27042 · hook package scan
- **Key Gate** — panel key login · HMAC-tagged session token rotation
- **Strike Counter** — HMAC-SHA256 integrity tag · max 3 strikes

## Output Structure

All tool output lands at:
```
/sdcard/Download/ALVSIA/
  IN/<MODULE>/    # optional input drop zone
  WORK/<MODULE>/  # intermediate / temp
  OUT/<MODULE>/   # final results ← always check here
```

---

© 2024–2026 ALVSIA PREMIUM TOOL · All rights reserved

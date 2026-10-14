# ALVISIA PRO 5.5.0

> **Telegram channel:** https://t.me/ALVSIA_PRO  
> **Developer / owner:** @OriginalOnwerALV — https://t.me/OriginalOnwerALV

## Project status

This repository contains the ALVISIA PRO Android source. The current license-only-login and UAsset/UEXP-inspector work is being validated on a development branch; it must not be treated as a production release until CI and on-device regression tests pass.

## Authentication

- The client UI uses a panel license key; the client OTP screen and OTP-derived `tool_ticket` flow are removed on the license-only branch.
- A successful panel login must issue a valid session token. Core fetch is bound to the same license and HWID and fails closed without a valid session.
- The panel's live login and core-fetch endpoints must enforce token validity, license/HWID binding, expiry, and device limits. Client-side checks are not a replacement for server authorization.
- The challenge/captcha handshake, if required by the deployed panel, is separate from the removed OTP screen.

## Tool catalog

| # | Tool | Function |
|---|---|---|
| 01 | PAK Unpack | Extract, list, info, CSV |
| 02 | PAK Rebuild | Repack, inject, encrypt, decrypt |
| 03 | PAK Compact | Delete entry, empty, clean |
| 04 | OBB Tools | Unzip, rezip, info |
| 05 | Lua Tools | Detect, analyze, decompile, clean, XOR |
| 06 | File Scan | Strings and hashes |
| 07 | Workspace | Clear WORK/OUT |
| 08 | Export Report | Session/file summary |
| 09 | Rebrand | Brand/channel replacement |
| 10 | SO Analyzer | Static binary inspection and string/XOR probes |
| 11 | Frida Tracer | Instrumentation helpers for authorized testing |
| 12 | XOR Suite | Single-byte/custom-key scans |
| 13 | Decrypt Engine | Supported AES/ZUC/SM4/SIMPLE1 operations |
| 14 | PAK Deep | Additional PAK format probes |
| 15 | String Recover | String and constant inspection |
| 16 | Lua Inject | Lua bytecode modification helpers |
| 17 | Anti-RE Audit | APK/Lua/SO posture reports; read-only UAsset/UEXP header and sidecar inspection |

The UAsset/UEXP inspector writes TXT and JSON reports with file size, SHA-256, raw header words, standard package-magic status, and companion-file detection. It does not modify the selected asset and does not claim to fully parse every Unreal Engine version or encrypted game format.

## Build and release

- GitHub Actions validates the source and builds an **unsigned release candidate** plus separate experimental obfuscation/protection candidates.
- Obfuscapk and XopProtector outputs are diagnostic candidates; a successful packer run does not prove device compatibility.
- Production signing requires the configured release secrets and must be verified against the expected production certificate fingerprint before distribution.
- Do not publish an APK as final until CI passes, the APK identity/signature are checked, and login plus representative Lua/PAK/OBB/Game Patch workflows have been tested on a real Android device.

For the current build and downloadable artifacts, open the repository's Actions tab:
https://github.com/ALVISIA8/alvsia-pro-550/actions

## Security and validation

The project uses defense-in-depth controls including TLS pinning, session gating, integrity checks, and native/runtime checks. These controls need regression testing to avoid false positives and must not be described as a guarantee that every tool works or as equivalent to commercial virtualization products.

Tool output is written under the app's configured workspace `IN/`, `WORK/`, and `OUT/` directories. Always verify the operation result and generated output rather than relying on a success-looking log line.

---

© 2024–2026 ALVISIA PRO

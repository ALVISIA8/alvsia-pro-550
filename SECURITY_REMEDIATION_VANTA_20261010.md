# ALVISIA PRO 5.5.0 R5.4 — VANTA review remediation

Date: 2026-10-10  
Scope: source branch `r5.4-native-rasp` and follow-up branch `r5.4-security-hardening-20261010`.

## Build provenance note

The APK signed in the preceding conversation came from the release-candidate artifact built from `main` commit `cc3584fb4470f85a9e82f42b100c7e0d3f88803f`. It is not the same source revision as `r5.4-native-rasp`. Do not infer R5.4 protections from that APK; use the CodeMagic build from this remediation branch and require `release_security_audit.txt` to pass before applying ReArK and signing.

## Verified in the R5.4 source

- The manifest does not declare `android.permission.DUMP`.
- The release Gradle packaging excludes `META-INF/version-control-info.textproto`.
- Release minification and resource shrinking are enabled through R8.
- Network security configuration and `Vault.certPinner()` both pin `alvsiapro.cc.cd`.
- Protected Python modules are stored as AES-GCM `.alv` payloads; the source release gate rejects plaintext copies of the protected modules.
- SessionGate encrypts persisted session fields with Android Keystore AES-GCM.
- Tamper and IntegrityBomb contain signing-certificate checks; SessionGate has a hard gate before tool execution.

## Fixes applied in this branch

- TLS pin validation no longer falls back to a request through an unpinned OkHttp client. Pin failures are reported and fail closed.
- Session strike integrity uses a dedicated Android Keystore HMAC-SHA256 key instead of relying on the non-exportable AES key's `.encoded` value or a fixed fallback.
- Session checks reject zero/invalid and future timestamps.
- Release ProGuard no longer retains line-number metadata.
- `security_release_check.py` now checks pinning/no-downgrade, manifest DUMP permission, VCS metadata stripping, release minification, Keystore HMAC, and timestamp checks.

## Findings that are not fully resolved by a client-only patch

- The native seal seed is a static constant in `librasp_guard.so`. The `.alv` payloads are encrypted at rest, but a determined reverse engineer can recover a static seed from the binary. Durable remediation requires a compatible server-side key-delivery / device-bound key agreement and an updated grant protocol; this branch warns about the limitation instead of claiming perfect secrecy.
- A client certificate pin is only safe when the current production SPKI and a planned backup/rotation procedure are verified. Do not disable pinning to work around a mismatch; update the pin only after verifying the production certificate.
- External URLs inside sealed payloads are not independently verified by the current source gate. They require reviewing the protected module source and adding pinned commit/hash checks before each download.
- User-space RASP cannot guarantee resistance to a compromised kernel, early injection, or a sufficiently privileged runtime hook.
- Ark VMP, RSProtect/ReArK, Virbox, and third-party RASP products are not automatically integrated just because their names appear in a checklist. Each requires its actual build artifact, compatible license/toolchain, and runtime test. R8/ProGuard and the existing native/Kotlin RASP are already represented in this source tree.

## Release acceptance criteria

A successful CodeMagic build proves compilation and source-gate checks only. Before distribution, verify the built APK's contents (including sealed payloads and native libraries), run the external packer(s) intended for the release, sign after packing, verify the release certificate, and test login, OTP, panel access, and all 17 tool modules on a physical device.

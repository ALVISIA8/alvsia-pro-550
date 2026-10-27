# ALVSIA PRO — Defensive Security Layers and Custom Dual-VM Plan
Date: 2026-10-27
Status: engineering plan; not a release claim.

## User requirement
The requested dual VM / Virbox-style protection is intended to be an ALVSIA-built, non-commercial, in-house design. Do not add a commercial Virbox SDK or imply compatibility with Virbox. Use ALVSIA-owned implementation and open-source components only after checking each project's license and Android/NDK compatibility.

## Existing baseline observed in main
- Android app version: 5.5.1-hardened, versionCode 97, minSdk 26, targetSdk 34, arm64-v8a.
- R8 minification/resource shrinking are enabled for release.
- Native target `rasp_guard` already exists; `rasp_guard.cpp` has a native integrity interpreter/mini-VM and checks for debugger/instrumentation indicators.
- Network security config has cleartext disabled and a SHA-256 SPKI pin for `alvsiapanel.unaux.com`. It currently documents no verified backup pin; certificate/key rotation must be planned before changing it.
- PermissionHelper source currently documents a first-screen all-at-once permission request; do not silently change this or remove RECORD_AUDIO. Android permission prompts are controlled by Android and cannot be silently auto-granted by an app.

## Recommended layers
1. **Build/repack integrity:** release signing, APK signer verification, DEX/native-library hashes generated during release, CI artifact audit. Keep secrets outside source control.
2. **Java/Kotlin and resources:** R8 optimized rules with keep-rule tests; resource shrinking; no claims that obfuscation makes secrets impossible to extract.
3. **Native RASP:** keep checks observational and scored rather than crashing/looping; combine multiple signals and avoid relying on one fragile libc prologue or timing heuristic. Log only privacy-minimized diagnostics.
4. **Network:** HTTPS with normal hostname/CA validation; SPKI pin with a verified backup pin and documented rotation procedure; server-side request timestamp/nonce/signature validation. Do not add custom crypto without threat model and review.
5. **Server authority:** license/session revocation and integrity decisions happen server-side. Treat client flags as untrusted; never embed a permanent server secret in the APK.
6. **Secrets and memory:** avoid persistent plaintext secrets; clear mutable buffers where feasible; Android/JVM copies and GC mean wiping is best-effort, not a guarantee.
7. **Lua/PAK pipelines:** safe workspace staging, size/time limits, bounded output, no arbitrary shell execution, input/output verification and rollback.
8. **Testing:** deterministic unit tests, emulator/device smoke tests, debug-vs-release checks, false-positive tests on ordinary rooted/developer devices, and signed APK inspection.

## Custom ALVSIA Dual-VM concept (not a commercial SDK)
- VM-A: a small, versioned bytecode interpreter for non-secret integrity policy and license-state decisions; fixed opcode allowlist, bounded instruction count, no arbitrary native calls, no dynamic code download.
- VM-B: a separate integrity-verification interpreter that validates build manifest/version, signer certificate digest, DEX/library digests, and policy result. Its output is evidence for the backend, not a client-side source of authority.
- Separate bytecode format/version and independent tests; use a generated manifest rather than hard-coded mutable constants. Add replay protection on the server.
- Fail safely: network outage should have a documented offline policy; avoid bricking legitimate installs due to transient false positives.
- Do not use anti-debugging to hide malicious behavior, bypass platform security controls, or silently evade user/OS visibility. Do not implement VPN/root/SSL-pinning bypass features from the referenced MVTOOLS list.

## External project review queue
- AabResGuard / AndResGuard: resource obfuscation; check license and current AGP compatibility.
- ProGuard / R8: established shrink/obfuscation pipeline; prefer current Android toolchain already in project.
- Free-RASP-Android / android-rasp / AndroidNativeGuard / AntiDebugandMemoryDump / WolfGuard / Mugen / O-MVLL / dProtect / paranoid / hidden-secrets-gradle-plugin / proguard-shield: evaluate one at a time for license, maintenance, native ABI, false-positive behavior, and supply-chain risk. Do not stack several RASP systems without conflict tests.
- MVTOOLS feature list is a feature wishlist, not evidence of implementation quality. “JADX breaker,” anti-dump claims, dynamic DEX encryption/loading, and anti-hook tricks require independent validation and can impair compatibility.

## Acceptance gates (must pass before release)
- Clean release build in CI / CodeMagic.
- Unit tests for VM opcode bounds, manifest hash verification, malformed bytecode, timeout/overflow, and version mismatch.
- APK audit: package ID, versionCode/name, permissions (including RECORD_AUDIO), signer v2/v3, certificate digest, DEX and native library presence, no debug flags.
- Verify panel login against `alvsiapanel.unaux.com`; do not fall back to the retired host.
- Install and exercise all 19 modules on an Android 13 arm64 device; verify Lua/PAK/OBB flows, UI/profile parity, audio-related function, and no regressions.
- No release-ready claim until the actual CI run and device tests pass.

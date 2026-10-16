# ALVISIA PRO 5.5.0 — Security / Logic Audit

## Materials audited
- Full ALVISIA source repository archive
- Signed APK supplied by the owner
- ALVISIA panel/API source archive
- ReArk 4.0 APK supplied by the owner

## Confirmed findings

### Critical
1. The source contains `app/src/main/cpp/CMakeLists.txt` and `rasp_guard.cpp`, but `app/build.gradle.kts` did not declare `externalNativeBuild`. The supplied final APK contained `librsprotect.so` from ReArk but did not contain `librasp_guard.so`. Therefore the intended native RASP bridge was not actually packaged in that APK and `NativeGuard` could fall back to Kotlin probes.
2. `PanelClient` had a TLS certificate-pinning fallback: after `SSLPeerUnverifiedException` / `CertificateException` it retried with an unpinned OkHttp client. That defeats the security property of certificate pinning during the exact failure mode pinning is intended to stop.
3. `tool_fetch.php` accepted the login session token independently of OTP authorization. OTP was enforced mainly on the client UI, not as a mandatory server-side state before protected material fetch.
4. The client used the OTP `tool_ticket` as the local `SessionGate` token when present, even though the server session token is the credential used by the protected API. This is an authorization-state mismatch.
5. The runtime UnLuaC assets were present as plaintext JARs in the supplied APK despite the repository's hardening documentation saying they should be sealed. The current `ToolEngine` also had a plaintext-asset fallback path.

### High
6. `NativeGuard.nativeScanFlags()` existed but was not called by `RaspEngine`, so the native detection layer was not participating in the normal RASP decision loop.
7. The real session token was injected into the Python process environment. This unnecessarily exposed a server credential to another runtime layer.
8. `R8/ProGuard` kept entire security/panel packages, which limits obfuscation of exactly the code an analyst would target.
9. The server repository contains operational credentials/secrets in configuration files. These must be rotated after source sharing/audit and moved to server-side environment/secret storage.
10. `tool_fetch.php` selects legacy `enc_data` / `enc_key_b64` columns which are not present in the visible current `vp_libs` schema/migrations. This makes the endpoint contract suspect and requires live DB verification before relying on it.

## Candidate hardening applied in the working copy
- Enabled Android CMake native build for `librasp_guard.so`.
- Removed the TLS pin downgrade/fallback.
- Routed security-event requests through the obfuscated Vault path.
- Made release session authorization process-local rather than plaintext SharedPreferences storage.
- Corrected local authorization to use the server session token, not the OTP ticket.
- Removed the real session token from the Python environment.
- Added native RASP scanning to the RASP tick loop.
- Switched runtime JAR installation to sealed `assets/nx/*` via `AssetVault`.
- Added a Codemagic build step to seal runtime assets before packaging.
- Added server-side OTP authorization state and made protected fetch/loader-key endpoints require it.
- Shortened server login session lifetime to 2 hours; OTP-authorized protected-material state is 1 hour.
- Fixed malformed intentional 404 PHP stubs.
- Reduced broad R8 keep rules.

## Not yet considered release-ready
The server asset/core transport is not yet a single verified protocol. The panel currently has Level-A asset encryption and partial-key generation, while the Android client's `fetchCore()` expects a different `CoreBundle`/Level-A format. This must be reconciled before final release.

The correct next design is a single server-authoritative protected-core protocol with:
- one-time request nonce;
- per-session/per-device key derivation;
- authenticated encryption (AES-GCM or ChaCha20-Poly1305);
- server-side OTP/session state;
- replay protection;
- file hash/version binding;
- no key+ciphertext delivered as independent reusable values;
- short-lived capability;
- explicit client verification of version, hash and context.

## Validation status
- Python source: syntax compilation passed.
- PHP panel source: syntax lint passed after candidate fixes.
- Git diff whitespace check: passed.
- Full Android build: not executed in this environment because Android SDK/NDK/Gradle distribution is not installed here.
- Real device functional test: not executed here.
- ReArk post-protection functional test: not executed here.

## Release rule
Do not distribute a candidate APK until:
1. CodeMagic release build succeeds.
2. `librasp_guard.so` is present in the unprotected release APK.
3. The asset plaintext JARs are absent from the unprotected APK.
4. ReArk protection succeeds.
5. The APK is re-signed with the ALVISIA release certificate.
6. The final signed APK passes certificate, install, startup, login, OTP, core fetch, and all 17 module regression tests.
7. Tamper tests confirm modified/re-signed APKs are rejected.

## Candidate source diff

```text
 README_FULL_HARDEN.md                              |   2 +-
 app/build.gradle.kts                               |   7 ++
 app/proguard-rules.pro                             |   6 +-
 app/src/main/java/com/alvsia/pro/MainActivity.kt   |   4 +-
 .../main/java/com/alvsia/pro/panel/PanelClient.kt  |  40 ++-----
 app/src/main/java/com/alvsia/pro/sec/RaspEngine.kt |  11 +-
 .../main/java/com/alvsia/pro/sec/SessionGate.kt    | 131 ++++++---------------
 .../main/java/com/alvsia/pro/tool/ToolEngine.kt    |  24 +---
 codemagic.yaml                                     |   9 ++
 9 files changed, 85 insertions(+), 149 deletions(-)
```

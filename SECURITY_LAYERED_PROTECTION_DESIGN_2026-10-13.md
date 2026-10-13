# ALVISIA PRO — Layered Android Protection Design
Date: 2026-10-13
Branch: security/vanta-audit-50-layer-20261013

## Goal
Increase reverse-engineering resistance and runtime threat visibility without breaking login, OTP, session/operation grants, Chaquopy, or LUA/PAK/OBB/game-patch features. This document is an integration design; a control is not considered active until code, CI evidence, and release-artifact/device tests prove it.

## Reference projects and intended use

- **Obfuscapk** — https://github.com/Mobile-IoT-Security-Lab/Obfuscapk
  - Use only as an isolated, optional post-build experiment on a disposable unsigned APK.
  - Evaluate string/class/method/resource obfuscation against app startup, reflection, JNI names, Chaquopy module imports, resource IDs, and Android manifest behavior.
  - Do not run it on the production artifact by default. Its apktool rebuild can change package metadata/resources and invalidates existing signatures; sign only after all transformations and verification.
  - Confirm the exact upstream repository, maintenance state, dependencies, and license before vendoring or automating it.

- **Talsec freeRASP** — https://github.com/talsec/Free-RASP-KMP
  - The ALVISIA project is a native Android app (Kotlin 1.9.24), not a Kotlin Multiplatform project. The KMP module currently targets Kotlin 2.2.0, so forcing that module into this build without a compiler/Compose migration would risk regressions.
  - Therefore this branch wires Talsec's official Android SDK counterpart, `com.aheaditec.talsec.security:TalsecSecurity-Community:19.2.3`, using the official threat-listener API and the existing release certificate hash.
  - Detection callbacks log minimal local event labels only; they do not send HWID, screenshots, license keys, or OTP, and a single heuristic does not terminate the app or grant/revoke a license.
  - Validate the dependency resolution and callback API in CI, then test release signing and false positives on real devices before release.

- **XopProtector** — https://github.com/xopJack/XopProtector
  - Treat its packer/native shell, DEX encryption, VMP, SO protection, and RASP as a separate, optional packaging experiment.
  - First validate on a disposable release build with no production secrets. Test application ID, manifest, native ABI, Chaquopy app.imy, .alv resources, JNI entry points, signing, upgrade compatibility, and crash-free launch.
  - Do not combine its shell/DEX transformation with Obfuscapk in the same first experiment. Change one protection layer at a time so regressions can be attributed.
  - Verify the exact release/tag, dependency provenance, license, and source before using the packer in CI. Never download and execute an unpinned latest binary in a release job.

## Layered design

1. **Build/reproducibility:** pin Gradle/AGP, JDK, NDK, Python packages and protection-tool versions; use immutable action/tool versions and produce a source commit + toolchain manifest.
2. **Kotlin/DEX:** R8 minification and resource shrinking stay enabled for release. Keep rules must be narrowly scoped for JNI, reflection, Compose, Chaquopy, and serialization; never blanket-keep the app or obfuscate entry-point names without tests.
3. **Python payloads:** generate authenticated .alv payloads before Chaquopy packages app.imy; verify exact inventory, AES-GCM authentication, build ID and absence of protected plaintext in the final APK. The native/build seed is extractable from a client APK and must not be treated as a server-side license secret.
4. **Native:** compile only required arm64-v8a unless other ABIs are deliberately supported; enable compiler hardening supported by the actual NDK; test JNI symbols and native library loading. Native RASP is defense-in-depth, not an authorization source.
5. **Runtime detection:** add freeRASP only after a versioned dependency/API review and debug/release smoke test. Combine its signals with existing native checks; do not let a heuristic alone grant access or silently destroy user data.
6. **Network/API:** enforce normal certificate validation everywhere. If pinning is used, include backup pins and an operational rotation plan; implement Python requests pinning at its actual call sites and test certificate failure/rotation. Keep license/session authorization on the server.
7. **Artifact integrity:** use trusted SHA-256 values from a version-controlled manifest or authenticated server metadata for downloaded tools/data. Verify before extraction/use, enforce size/time limits, reject path traversal, and fail closed on digest mismatch.
8. **Android permissions:** request only feature-required permissions at point of use; prefer Storage Access Framework for user-selected files. All-files access must be optional, explicitly explained, and gracefully denied. No permission bypass.
9. **Post-build packers:** Obfuscapk and XopProtector remain opt-in until a dedicated CI lane demonstrates manifest/package stability, valid signatures, successful install/upgrade, login/OTP, all tool menus, and native/Python startup.
10. **Release assurance:** inspect final signed APK; verify signer SHA-256, APK v2/v3 signature, payload inventory, merged manifest, network config, native libraries, and artifact SHA-256. Keep unsigned, transformed, and signed artifact hashes distinct.

## Required gates before enabling another protector

- [ ] Confirm license and provenance of the exact pinned version.
- [ ] Run transformation on a throwaway APK; never overwrite the known-good input.
- [ ] Compare manifest, package ID, permissions, resources, DEX/native inventory, and Chaquopy assets before/after.
- [ ] Install on Android 8/API 26 and a current Android version; test fresh install and upgrade over the last release.
- [ ] Test login, OTP, session expiry/re-auth, operation grants, network failures, denied permissions, LUA, PAK, OBB, dump, game patch, and exit.
- [ ] Verify tampered payload and bad download digest are rejected.
- [ ] Verify legitimate devices are not blocked by RASP false positives.
- [ ] Verify final signature and artifact digest after the last transformation.
- [ ] Enable in production only after all checks pass and rollback path is documented.

## Current state
Branch status: the Talsec Android SDK dependency and startup listener are wired; CI has been updated to attempt both Obfuscapk and XopProtector on isolated candidate APKs. At the time of this edit, the new workflow run is pending, so no successful build or working transformed APK is claimed. The exact Free-RASP-KMP library is not directly integrated because its current source requires Kotlin 2.2.0 while this Android app is on Kotlin 1.9.24; a Kotlin/Compose migration would need a separate tested change.

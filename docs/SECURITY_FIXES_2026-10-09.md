# ALVISIA PRO 5.5.0 — Security and dispatch corrections (2026-10-09)

This note records the release-candidate corrections on branch `fix/session-gate-otp-20261009`.

## Changes

- Python APK-session checks now require both the session marker and a 64-character hexadecimal `ALVSIA_SESSION_TOKEN`. This rejects the old marker-only path, but token shape is **not** cryptographic proof and does not replace server-signed per-operation grants.
- Release builds now fail closed when OkHttp certificate pinning fails. The unpinned retry remains available only in debug builds. The current panel configuration has one SPKI pin, so the live pin must be verified and a separately controlled backup pin should be prepared before broad release to reduce certificate-rotation lockout risk.
- Tool input requirements now come from each `SubTool.needsFile` declaration. This prevents file-requiring actions such as Decrypt Engine, String Recover, and Export Report from being incorrectly treated as no-input actions.

## Validation boundary

GitHub Actions checks source compilation, regression tests, Gradle build, and native RASP packaging. These checks do not prove every operation works on a physical Android device. A release should still receive an on-device smoke test across the 17 modules and the actual panel login/OTP flow. Plaintext Python modules and the absence of verified commercial Double VM/Virbox SDK integration remain separate security work items.

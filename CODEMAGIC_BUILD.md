# ALVISIA PRO 5.5.0 — CodeMagic Release Build

## Source

- Repository: `ALVISIA8/alvsia-pro-550`
- Branch: `main`
- Configuration: `codemagic.yaml`
- Package: `com.alvsia.pro`

## One-time CodeMagic setup

1. Open the app in CodeMagic and select `main` as the build source.
2. In **Team settings → Environment variables**, create an environment-variable group named `signing`.
3. Add these variables to that group:
   - `CM_KEYSTORE`: Base64-encoded release JKS keystore (single line).
   - `CM_KEYSTORE_PASSWORD`: release keystore password.
   - `CM_KEY_ALIAS`: `alvsia`.
   - `CM_KEY_PASSWORD`: key password (if identical, use the same value as `CM_KEYSTORE_PASSWORD`).
4. Attach the `signing` group to the workflow. Do not commit the keystore or passwords to GitHub.

## Build and release checks

The workflow runs Python compilation and regression tests, Android unit tests, and `assembleRelease`. It checks that the APK contains `lib/arm64-v8a/librasp_guard.so`, signs the release APK, verifies the APK signature, and rejects a signer certificate that does not match the pinned ALVISIA release certificate.

The workflow publishes these artifacts only after successful verification:

- `ALVISIA_PRO_5.5.0_signed.apk`
- `ALVSIA_PRO_5.5.0_release.sha256`
- `ALVSIA_PRO_5.5.0_signing-verification.txt`
- `build_full.log`

## Run

Select the `alvisia-android` workflow and click **Start new build**. Do not distribute a build unless CodeMagic finishes successfully and the signed APK, signer verification, and SHA-256 artifact are present.

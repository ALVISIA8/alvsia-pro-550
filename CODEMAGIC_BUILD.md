# CodeMagic Release Build — ALVSIA PRO 5.5.1-hardened

This guide matches the workflow in `codemagic.yaml`. The release workflow is named **ALVSIA PRO 5.5.1-hardened** and only runs for pushes to `main`.

- Repository: `ALVISIA8/alvsia-pro-550`
- Branch: `main`
- Package: `com.alvsia.pro`
- Version: `5.5.1-hardened` (`versionCode 97`)
- Expected signed APK: `ALVISIA_PRO_5.5.1-hardened_signed.apk`

## 1. Connect the repository

In CodeMagic, add `ALVISIA8/alvsia-pro-550` and select the `codemagic.yaml` workflow `alvisia-android`. Confirm the workflow uses the `main` branch.

## 2. Configure release signing

Create an environment-variable group named exactly `signing` and attach it to the workflow. Set these variables:

- `CM_KEYSTORE_PASSWORD` — keystore password (secret).
- `CM_KEY_ALIAS` — `alvsia`.
- `CM_KEY_PASSWORD` — private-key password (secret); it may equal the keystore password.
- **One keystore source:** either `CM_KEYSTORE_PATH` pointing to a keystore file available to the build, or `CM_KEYSTORE` containing the Base64 text of the release keystore.

The workflow also accepts `CM_KEYSTORE` as a readable file path if CodeMagic exposes it that way. Do not put the keystore, password, or Base64 contents in Git or chat.

The certificate must match the pin in `app/build.gradle.kts`:
`99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c`.

The release job intentionally **fails** if signing configuration is missing or if the resulting certificate does not match. It does not publish an unsigned APK as a successful release.

## 3. Run the release build

Push the reviewed release source to `main`, or start the `alvisia-android` workflow on `main` if manual workflow start is available in the CodeMagic UI. Pull-request builds are not the release workflow.

The workflow:
1. Checks the branch and signing configuration.
2. Runs source security checks and seals Python modules/assets with a fresh per-build seed.
3. Builds the release APK and audits its contents/metadata.
4. Signs with v2/v3 enabled and v1 disabled.
5. Verifies signature, certificate pin, package name, version, alignment, and final APK contents.

Download `ALVISIA_PRO_5.5.1-hardened_signed.apk` from the successful CodeMagic build's Artifacts section. Also retain `build_full.log` for diagnosis.

## Troubleshooting

- **Missing signing variables:** verify the exact group name `signing` and attach it to `alvisia-android`.
- **Invalid Base64:** create Base64 from the intended release keystore and save the full output in the secret `CM_KEYSTORE`; do not include line breaks or surrounding quotes.
- **Certificate mismatch:** use the release keystore whose certificate matches `CERT_SHA256`. Do not remove the certificate check to bypass the error.
- **Build succeeded but app was not tested:** CI success proves the automated checks passed; still install the exact signed APK and verify login against the current panel and exercise the 19 modules on a device before public release.

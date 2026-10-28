# Setup CodeMagic — ALVSIA PRO 5.5.2-hardened

Workflow: `alvisia-android` (`ALVSIA PRO 5.5.2-hardened`)  
Release branch: `main`  
Package: `com.alvsia.pro`  
Version: `versionCode 98`, `versionName 5.5.2-hardened`

## 1. Connect the repository

1. Connect GitHub repository `ALVISIA8/alvsia-pro-550` in CodeMagic.
2. Ensure CodeMagic reads `codemagic.yaml` from `main`.
3. Add an environment variable group named exactly `signing` and attach it to this workflow.

## 2. Configure release signing secrets

Set these variables in the CodeMagic UI. Do not commit the keystore, passwords, or Base64 keystore content.

- `CM_KEYSTORE_PATH`: path to an uploaded keystore file available to the build, **or**
- `CM_KEYSTORE`: Base64-encoded contents of the release keystore.
- `CM_KEYSTORE_PASSWORD`: keystore password.
- `CM_KEY_ALIAS`: `alvsia`
- `CM_KEY_PASSWORD`: private-key password; it may equal the keystore password.

Use one of the two keystore sources above, not a placeholder. The workflow fails early if the keystore or password is missing or invalid.

To produce Base64 in Termux without changing the keystore:
```bash
base64 -w 0 "$HOME/ALVISIA_KEYSTORE/alvsia-release.jks"
```
Copy the output directly into CodeMagic's secret variable `CM_KEYSTORE`. Do not send the output or passwords in chat or commit them to GitHub.

The app expects signing certificate SHA-256:
`99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c`

The final signing step rejects a keystore whose certificate does not match this value.

## 3. Run the release workflow

The workflow is configured to run on pushes to `main`. After the signing group is configured, start the `alvisia-android` workflow on `main` in CodeMagic or push an approved commit to `main`.

The pipeline validates secrets, runs source checks, seals Python modules and runtime assets, builds the release APK, signs it with V2/V3 (V1 disabled), and verifies the exact final signed APK. Expected artifact:

`ALVISIA_PRO_5.5.2-hardened_signed.apk`

Download only this signed artifact from a successful CodeMagic build. GitHub Actions validation APKs are **unsigned** and are not release-ready.

## 4. Unaux runtime verification still required

The Android source pins HTTPS to `alvsiapanel.unaux.com` using SPKI SHA-256 `84+S6cn1vo+IjlQMR5mvqIe5XKMPh28WV9xYVtFKTkk=`. CA and hostname verification remain enabled. CI verifies the configured pin policy, but it cannot prove the current live host presents that SPKI or that the hosting-side grant key/database configuration is installed correctly.

After deployment, test on-device:
1. Login using a valid license and device.
2. Invoke one operation from each module group; confirm a fresh RS256 grant is accepted.
3. Confirm invalid/expired grants fail closed.
4. Confirm ordinary login and assets still work over HTTPS.
5. Check the signed APK certificate, package/version, and all required modules.

Do not disable pinning or weaken grant validation just to bypass a failed live test. If the live SPKI differs, re-measure it from the actual host and verify the host identity before changing the pin.

## Troubleshooting

- `Missing CM_KEYSTORE_PATH` / `CM_KEYSTORE`: configure one valid keystore source in group `signing`.
- `Missing CM_KEYSTORE_PASSWORD`: correct the variable name and value in group `signing`.
- `CM_KEYSTORE is not valid base64`: regenerate Base64 from the release keystore and copy the complete output.
- `certificate does not match`: use the intended release keystore; do not remove the app certificate check.
- Grant rejected or TLS pin mismatch: verify the live Unaux endpoint, deployed `operation_grant.php`, matching private/public RSA key, and live SPKI. Do not claim the release is production-verified until those checks pass.

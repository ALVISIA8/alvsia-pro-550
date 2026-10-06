# ALVISIA PRO 5.5.0-R5.1 Security Update

## Changes
- Removed/blocked legacy client-side auth bypass paths (`ALVSIA_SOFT_AUTH`, `ALVSIA_APK_SESSION`).
- Tool execution requires a server-issued, short-lived RSA-SHA256 operation grant bound to session, device, build, signing certificate and live source measurement.
- RASP/tamper degraded state is now fail-closed at `SessionGate.allowTools()`; detected hostile runtime cannot continue into the tool engine.
- Added `tools/security_release_check.py` and wired it into `assembleRelease` as `securityReleaseCheck`.
- Version bumped to `versionCode 96`, `versionName 5.5.0-R5.1`.
- Legacy panel endpoints remain untouched; the operation-grant endpoint is additive.

## Build

```bash
python3 tools/security_release_check.py
./gradlew :app:assembleRelease
```

The release build will fail if known client-side bypass markers or RSA private-key material are found in app source, or if required operation-grant hooks are missing.

## Server requirement

Deploy the additive `operation_grant.php` endpoint from the panel deployment package. Keep its RSA private key outside the public webroot and outside GitHub. The APK contains only the public verification key.

## Important limitation

This update hardens the authorization and runtime enforcement path. Chaquopy Python source is still part of the APK unless the project is migrated to a true native/custom-VM execution layer. Do not describe this build as impossible to reverse-engineer.

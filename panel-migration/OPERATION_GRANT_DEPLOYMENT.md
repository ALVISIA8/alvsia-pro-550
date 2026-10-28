# RSA Operation Grant — Unaux panel deployment

This directory contains the server endpoint source for the new panel: `/api/operation_grant.php`.

## Runtime contract

- Method: POST JSON.
- Requires an existing panel session from `vp_sessions`, a matching active license from `vp_license_keys`, matching HWID, and an unexpired session and license.
- Request fields: `license`, `hwid`, `session_token`, `session_id`, `operations[]`, `build_id`, `manifest_hash`, `tool_hash`.
- `session_id` is the full lowercase SHA-256 hex digest of `session_token` (64 hex characters).
- Response: `{"status":"success","proof":{...,"signature":{"alg":"RS256","kid":"alvsia-r4-20260923","value":"..."}}}`.
- Canonical signed message is the exact `ALVSIA-R4` newline-delimited format in the endpoint and APK verifier.
- Grant TTL is 180 seconds. Missing key, DB errors, invalid session, wrong build, invalid measurement, and unknown operations fail closed.

## Private key

Never commit the RSA private key or place it inside the public `htdocs` directory. The endpoint accepts either:

- `OPERATION_GRANT_PRIVATE_KEY_FILE`: absolute path to the PEM outside webroot; or
- `OPERATION_GRANT_PRIVATE_KEY`: PEM from the hosting environment.

If the old RSA private key that matches the APK's embedded public modulus is available, configure that exact key. Do not generate a new key unless prepared to update the APK public modulus and rebuild/release the APK in the same coordinated rotation.

On shared hosting without environment-variable controls, place the PEM in a private directory outside `htdocs` and configure the PHP-FPM/Apache environment if supported. Do not silently fall back to a key stored in a publicly reachable directory.

## Deployment checklist

1. Back up the current panel files and database.
2. Confirm `config.php` defines `db()` and that the database schema uses `vp_sessions` and `vp_license_keys` as queried by this endpoint.
3. Upload this file to the panel's actual `htdocs/api/operation_grant.php` location beside `config.php` and `sec_lib.php`.
4. Configure the matching private key outside webroot and verify PHP OpenSSL is enabled.
5. Confirm unauthenticated, expired, revoked, blocked, wrong-HWID, wrong-build, wrong-measurement, and unknown-operation requests are rejected.
6. Test a valid grant and verify its signature with the APK's public modulus. Confirm the signature and fields match the Android/Python verifier exactly.
7. Only after server testing, integrate the APK client request path and run a signed release build. A server endpoint alone does not activate RSA grants in an APK that does not call it.

## Important

This is source for deployment, not proof it is already uploaded to the live Unaux panel. The current repository has no direct hosting-file access, so deployment and live endpoint verification must be completed against the panel's actual files.
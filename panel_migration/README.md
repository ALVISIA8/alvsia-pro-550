# New-panel migration deployment patch

Target base: `https://alvsiapanel.unaux.com/api`

## Required panel-side endpoint

The new-panel ZIP does not contain `api/operation_grant.php`, but the APK's Python core intentionally fails closed for privileged PAK/OBB actions unless it receives a short-lived RSA-signed grant.

1. Copy `panel_migration/api/operation_grant.php` to the new panel's `api/operation_grant.php`.
2. Keep the existing `api/config.php` and its `session_validate()` / `db()` helpers. The endpoint validates the panel's `vp_sessions` session and license/device binding.
3. Configure the existing R4 RSA private key on the server as `ALVSIA_OPERATION_GRANT_PRIVATE_KEY`, or place it in `api/operation_grant.pem` with restrictive filesystem permissions. It must match the public modulus embedded in the shipped `alvsia_core.py`; do not generate a different key.
4. Add `operation_grant.pem` to the API directory's web-deny rules (example in `panel_migration/api/.htaccess.addition`). Never commit the PEM.
5. Confirm the endpoint returns `{"ok":true,"grant":{...}}` and that `expires_at - issued_at` is at most 180 seconds. The endpoint currently issues 120-second grants and fails closed if the signer is missing or mismatched.

## Other migration behavior

- APK login uses only `/api/captcha.php` and `/api/connect.php`; legacy `g.php` / `s.php` fallbacks are removed.
- The new panel's `get_asset.php` returns metadata and a one-time download token, not the old opaque CoreBundle. The APK therefore uses its built-in tool catalog/engine fallback instead of treating that JSON response as executable bytes.
- TLS still validates the host certificate against Android's system CA store. The old host's SPKI pins are not reused for the new hostname. Add a new SPKI pin only after verifying the deployed certificate chain.

## Release gate

Do not merge/release until CI passes and the deployed panel endpoint has been tested with a real licensed test account. Check login, refresh/session expiry, grant signing, and at least one protected PAK and OBB operation on-device. The 19-menu catalog must be regression-tested before release.

CI trigger note: this migration branch is intentionally separate from `main`; merge only after the new endpoint is deployed and protected-operation/device tests pass.

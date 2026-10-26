# ALVSIA PRO — New panel migration

This branch removes the retired `alvsiapro.cc.cd` login/CoreBundle/grant URL contracts from the active Android path and makes the APK target:

- `https://alvsiapanel.unaux.com/api/captcha.php`
- `https://alvsiapanel.unaux.com/api/connect.php`
- `https://alvsiapanel.unaux.com/api/refresh_session.php`
- `https://alvsiapanel.unaux.com/api/get_asset.php`
- `https://alvsiapanel.unaux.com/api/download_asset.php`

## Design decisions

1. Login follows the new panel's captcha + PoW + AES-CBC proto-2 handshake.
2. The old `tool_fetch.php` / CoreBundle contract is not emulated by misusing `get_asset.php`. The APK uses its bundled tool catalog and local engines; all 19 menus remain local. Dynamic CoreBundle delivery is not required by the new panel contract.
3. The new panel has no operation-grant endpoint, so the APK uses its existing login/session validation (`SessionGate`) plus SHA-256 device/session binding before tool dispatch. The missing grant API is not called, and the old panel grant contract is removed.
4. This is a panel-aligned session model; it does not claim per-operation server grants because the new panel does not support them. Protected operations are authorized by the authenticated session and local identity-binding checks, not by a server-signed per-operation grant.
5. TLS hostname and CA validation remain enabled. The old hostname's SPKI pins were removed rather than copied to a different host. A new-host SPKI pin set must be added only after the live certificate chain has been measured and a backup pin verified.

## Release gates

- Confirm the new panel's deployed API paths and login handshake on a real device.
- Confirm the existing panel login/session contract supplies the expected token and device identity to the APK. Do not deploy or call an operation-grant endpoint that the panel does not provide.
- Confirm all tool engines and 19 main menus/submenus work with the bundled runtime.
- Run the Android release workflow and inspect its logs and APK artifact. CI success alone does not prove runtime login or every tool works.
- Install the signed APK and smoke-test login, session expiry, PAK/OBB protected actions, Lua/Python, file I/O, and TLS failures.
- Verify the new host's live certificate chain before deciding whether to add SPKI pinning; do not reuse pins from the retired hostname.

## Current limitation

The new-panel source path no longer depends on unavailable grant/CoreBundle endpoints. Android debug and release CI have passed on the latest checked revision, but login and the 19-menu smoke test still require a real device. TLS currently uses platform CA and hostname validation; SPKI pinning is not enabled because the new host's live certificate chain has not been measured.

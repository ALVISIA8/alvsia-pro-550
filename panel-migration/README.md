# ALVSIA PRO — New panel migration

This branch removes the retired `alvsiapro.cc.cd` login/CoreBundle/grant URL contracts from the active Android path and makes the APK target:

- `https://alvsiapanel.unaux.com/api/captcha.php`
- `https://alvsiapanel.unaux.com/api/connect.php`
- `https://alvsiapanel.unaux.com/api/refresh_session.php`
- `https://alvsiapanel.unaux.com/api/get_asset.php`
- `https://alvsiapanel.unaux.com/api/download_asset.php`
- `https://alvsiapanel.unaux.com/api/operation_grant.php` (adapter source is in this directory and must be deployed to the new panel)

## Design decisions

1. Login follows the new panel's captcha + PoW + AES-CBC proto-2 handshake.
2. The old `tool_fetch.php` / CoreBundle contract is not emulated by misusing `get_asset.php`. The APK uses its bundled tool catalog and local engines until a versioned, authenticated CoreBundle transport is deliberately implemented on the new panel.
3. High-privilege PAK/OBB operations still require a server-signed RS256 proof. The signed `session_id` is the full lowercase SHA-256 hex digest of the 64-hex session token and is compared consistently by Kotlin, the panel endpoint, and Python. Grant lifetime is exactly 180 seconds. No client-side bypass was added.
4. `operation_grant.php` is a deployment adapter, not a live server change. Deploy it into the **new panel's** `api/` directory and configure `OPERATION_GRANT_PRIVATE_KEY_FILE` or `OPERATION_GRANT_PRIVATE_KEY` outside source control. Its signing public key must match the RSA modulus embedded in `app/src/main/python/alvsia_core.py`; otherwise the engine correctly rejects the proof.
5. TLS hostname and CA validation remain enabled. The old hostname's SPKI pins were removed rather than copied to a different host. A new-host SPKI pin set must be added only after the live certificate chain has been measured and a backup pin verified.

## Release gates

- Confirm the new panel's deployed API paths and login handshake on a real device.
- Deploy and test the RSA grant endpoint; verify the signature against the APK's embedded public key, TTL <= 180 seconds, device/session binding, expiry and replay behavior.
- Confirm all tool engines and 19 main menus/submenus work with the bundled runtime.
- Run the Android release workflow and inspect its logs and artifact. CI success alone does not prove runtime login or every tool works.
- Install the signed APK and smoke-test login, session expiry, PAK/OBB protected actions, Lua/Python, file IO, and TLS failures.

## Current limitation

The source branch can be built without the retired CoreBundle endpoint, but the new panel's operation-grant endpoint must be deployed separately. Until that is deployed and tested with the matching private key, protected PAK/OBB operations will fail closed by design. Certificate pinning for the new hostname is also pending live certificate verification.

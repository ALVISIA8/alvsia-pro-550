# Unaux RSA Operation Grant contract

Aligned to the upgraded Unaux panel contract, not the legacy ALVSIA-R4 proof format.

- Endpoint: `/api/operation_grant.php`
- Request: POST JSON `session_token`, `hwid`, `build_id`, `operation`, `request_id`.
- Response: `status=ok` and compact `grant_token` JWT.
- Algorithm: RS256; KID `alvsia-unaux-rsa1`; Build ID `ALVSIA-UNaux-20261028-RSA1`; issuer `https://alvsiapanel.unaux.com`; audience `com.alvsia.pro`.
- TTL: maximum 180 seconds.
- The APK verifies signature, issuer, audience, KID, build, operation, time window, session hash, and device hash.
- Never commit the private key. The endpoint reads it from `api/.private/operation_grant_private.pem`; confirm the host denies direct access to that directory.
- Runtime compatibility with the live hosting and database must be verified after deployment; CI cannot prove the live host.

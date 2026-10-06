# Additive R5 operation-grant endpoint

`operation_grant.php` is the server authority for tool execution. Deploy it under the panel API namespace used by `Vault.pathGrant()`.

It must include the existing panel `config.php`, and `ALVSIA_OPERATION_GRANT_PRIVATE_KEY_FILE` must point to a private RSA key stored outside the public webroot.

Do **not** commit the private key or production credentials.

Legacy endpoints such as login/OTP/fetch are intentionally not replaced by this file.

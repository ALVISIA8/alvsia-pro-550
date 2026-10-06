# ALVISIA PRO 5.5.0 R5

- Removed client-side auth bypass flags.
- Added short-lived RSA-signed operation grants.
- Grant is bound to session, HWID, build, certificate and runtime measurement.
- Existing legacy panel endpoints are unchanged.
- Production panel secrets are moved outside htdocs.
- The operation-grant private key must never be committed to GitHub.

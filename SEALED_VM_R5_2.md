# ALVISIA PRO R5.2 — Sealed Execution Layer

R5.2 moves the sensitive Python implementation out of plaintext APK assets.

Protected modules are AES-256-GCM sealed into `app/src/main/python/sealed/*.alv`.
`sealed_loader.py` installs a guarded import loader. The loader requires both:
1. a native build-bound seed supplied by `NativeGuard`;
2. a live server `ALVSIA_OPERATION_GRANT`.

The protected source is decrypted only in the Python process and is never written
as `.py` files to application storage.

This is stronger than plaintext Chaquopy packaging, but it is still not an
unbreakable VM. A determined runtime attacker can instrument a live process.
The server grant, native RASP, certificate binding and fail-closed release gate
remain the trust boundary.

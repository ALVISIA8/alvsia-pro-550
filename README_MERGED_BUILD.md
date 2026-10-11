# ALVISIA PRO 5.5.0 — canonical build route

## Single production release door

**Production APKs are built and signed only by the CodeMagic workflow on branch `main`.** The workflow checks the release signing variables, creates a fresh sealed-payload seed per build, runs regression/security checks, seals Python and JAR assets, runs AndResGuard, audits the APK, verifies the pinned release certificate, and emits a checksum. Do not commit signing keys, passwords, or a reusable seed.

## Local/CI preflight entrypoint

- Debug compile/tests: `./BUILD_ONE_DOOR.sh debug`
- Release candidate build/audit: `ALVSIA_SEAL_SEED_HEX=<fresh-64-hex-seed> ./BUILD_ONE_DOOR.sh release`

The release entrypoint fails closed if the seed is missing or malformed. It checks the bundled Python/tool regression suites, Android unit tests, native RASP library presence, and APK static audit. It does **not** replace CodeMagic's production signing gate or a real-device smoke test.

## Licensed protection stages

The Virbox step is conditional on the licensed vendor CLI and profile being configured. A build without those inputs must not be described as Virbox-protected. No claim is made that a Dual VM or T Protector vendor runtime is present unless its actual artifact and runtime tests prove that.

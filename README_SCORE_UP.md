# Score-up (real logic)

## Changes
1. **Server-first core** — panel `tool_fetch` preferred; fauna only if no server engine.
2. **Fauna decoy** — `assets/fauna/panda.dat` is not a real engine (dump = useless).
3. **No disk engine** — `installEngineBytes` keeps bytes in RAM only; deletes legacy `mango_kernel.py`.
4. **Signature gate** — if `BuildConfig.CERT_SHA256` set and mismatch → block after OTP, report Telegram.
5. **No core.ok marker** on disk.

## Owner: lock signature (raises anti-repack)
1. Build + sign + install release once.
2. Log cert: call or temporary debug print `Tamper.signingCertSha256(context)`.
3. Put hex into `app/build.gradle.kts`:
   `buildConfigField("String", "CERT_SHA256", "\"YOUR_HEX_HERE\"")`
4. Rebuild + ReArk + re-sign with **same** keystore.

## Expected score impact
~6.5–7.5 → **~7.5–8.0** when CERT_SHA256 filled + ReArk + panel serves engine.

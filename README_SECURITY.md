# ALVSIA 4.6 — Security mapping (guide → implemented)

| Guide item | Status in this source |
|------------|------------------------|
| PyArmor on Chaquopy bridge | **Not shipped** — PyArmor trial emits **linux x86_64** runtime, breaks Android arm64. Bridge comment-stripped; core stays server/fauna. |
| Certificate pinning | **Yes** — OkHttp `Vault.certPinner()` + `network_security_config` pin-set + pin-fail fallback |
| Strip native symbols | **Yes** — `ndk { debugSymbolLevel = "NONE" }` release + abi arm64 only |
| R8 / ProGuard | **Yes** — minify + shrink + aggressive repackage |
| Anti-tamper | **Yes** — `Tamper.kt` (pkg, debuggable, cert SHA-256) |
| Anti-Frida / debug | **Yes** — `Guard` + `FridaProbe` (maps, paths, ports 27042/27043, TracerPid) |
| Signature verification | **Yes** — optional `Tamper.expectedCertSha256` after your release sign |
| String hide | **Yes** — `Vault` rebuild + `StrHide` |
| Threat Telegram | **Yes** — `ThreatReport` → `/api/security_event.php` |
| ReArk / packer | **Post-build** (your pipeline) — not inside Gradle |

**Do not** hard-kill process on splash (past false positive). Signals → Telegram + `Guard.degraded`.

## After sign (owner)
1. Install release APK once, log `Tamper.signingCertSha256(context)`.
2. Put hex into `Tamper.expectedCertSha256`.
3. Rebuild + ReArk.

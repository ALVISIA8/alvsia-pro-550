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

## Verified release layers (main)

- R8 code shrinking/obfuscation and Android resource shrinking.
- AES-GCM sealed Python payloads and sealed JAR assets; the seal input is generated per CI/CodeMagic build and injected into the native guard.
- ALVISIA native RASP probes, plus Securevale Android RASP 0.7.1 initialization and emulator/debugger/root checks.
- TLS certificate pinning, session TTL/HMAC checks, release APK audit, and tool-route regression tests.

## Deliberately not marked complete

- AabResGuard is an AAB resource obfuscator; the current delivery is an APK. Its upstream repository is archived, so it is not silently added to the APK pipeline.
- AndResGuard is a separate APK repackaging tool with legacy Gradle integration; it needs an isolated post-processing test before it can replace release artifacts.
- Dual VM / VIRBOX and XopProtector post-build packing are not considered integrated merely because they are listed. VIRBOX also requires the appropriate vendor tooling/licence. These remain separate release gates until the protected APK passes launch, login/OTP, and all-tool runtime regression tests.

A passing CI build proves compilation and the automated checks above, not immunity to reverse engineering or successful on-device execution of every feature.

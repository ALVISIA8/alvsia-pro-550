# Grade-A RASP stack (ALVSIA 4.7)

## Repo → apa yang dipasang di project ini

| Repo / tech | Status di ALVSIA |
|-------------|------------------|
| **R8 / ProGuard** (Google + Guardsquare lineage) | ON release minify+shrink |
| **securevale/android-rasp** | dependency `0.7.1` + init reflection |
| **talsec freeRASP** | TIDAK di-embed default (butuh plugin/license token build); pola threat sama di RaspEngine |
| **AndroidNativeGuard** (archived) | Pola di `rasp_guard.cpp` + NativeGuard |
| **AntiDebugandMemoryDump / DetectFrida** | TracerPid, maps, ports, path di native |
| **AndResGuard / AabResGuard** | Optional post-build (ReArk + resource shrink R8) |
| **o-mvll / dProtect** | Butuh LLVM custom toolchain — tidak di Codemagic standar; gunakan ReArk VMP |
| **Paranoid / hidden-secrets** | Vault + StrHide runtime string rebuild |
| **proguard-shield style rules** | proguard-rules.pro agresif |
| **MITM** | OkHttp pin + network_security_config |
| **Anti-repack** | CERT_SHA256 + Tamper |
| **RAM tool** | RamToolVault + wipe on RASP threat |
| **Panel** | session bind + rate limit (PANEL_HARDEN_9) |

## Runtime policy
- Frida / debugger / hook maps / sig mismatch → wipe RAM tool + `SessionGate` off
- Root / emulator → report Telegram, degrade, tool masih boleh (device member sering root)

## Build
Codemagic butuh NDK untuk CMake `librasp_guard.so`.
Setelah build: ReArk → sign keystore ALVSIA.

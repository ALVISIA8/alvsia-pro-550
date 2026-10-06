# ALVSIA 4.6 — Full harden (sekali jalan)

## Layers in this source
1. R8 minify + shrink + repackage
2. NDK debugSymbolLevel NONE
3. TLS pin + fallback
4. Guard + FridaProbe + EnvProbe (root/magisk hint)
5. Tamper + CERT_SHA256 (keystore ALVSIA)
6. SessionGate (tools blocked without OTP session / bad cert)
7. Server-first core, RAM engine, fauna decoy
8. Bridge Python thinned (no feature map strings)
9. unluac.jar **removed from APK assets** (optional pack for panel)
10. ThreatReport → security_event.php
11. RELEASE_SIGN_TERMUX.sh — wajib sign keystore kuat setelah ReArk

## Build order
1. Push this source → Codemagic assembleRelease
2. ReArk protect APK
3. On Termux: `bash RELEASE_SIGN_TERMUX.sh /sdcard/Download/YOUR_REARK.apk`
4. Install SIGNED apk only

## Never distribute
- APK signed with Android debug / MUNDO only
- STORE_PASSWORD.txt in public chat

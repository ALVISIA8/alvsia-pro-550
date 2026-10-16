# ALVISIA PRO — Source Final Changelog
**Date:** 2026-10-15  
**Base:** PROJECT_SOURCE_BASE + HARDENED_SOURCE_REFERENCE/alv-inner merge  
**Target:** Single consistent, buildable source — all protections intact

---

## PERUBAHAN KRITIS

### 1. OTP Dihapus Sepenuhnya
- `app/src/main/java/com/alvsia/pro/ui/otp/OtpScreen.kt` — **DIHAPUS**
- `PanelClient.kt` — `requestOtp()` dan `verifyOtp()` **DIHAPUS**, `OtpResult` data class **DIHAPUS**
- `MainActivity.kt` — **DITULIS ULANG**; alur: `splash → login(key) → loading → home`
  - Session token diambil langsung dari respons `login()` (`session_token` field)
  - `fetchCore()` dipanggil dengan `sessionToken` dari login, bukan `toolTicket` dari OTP
  - Seluruh cabang `"otp"` di screen state machine **dihapus**
- `LoginScreen.kt` — teks "OTP will be sent" diganti "KEY AUTH SYSTEM", button "CONTINUE" → "LOGIN"
- `alvsia_bridge.py` dan `alvsia_bridge_impl.py` — error message OTP diperbaiki

### 2. Bug Instance Variables PanelClient Diperbaiki
- `sessionToken`, `lastLicense`, `lastHwid`, `toolTicket` sebelumnya **tidak dideklarasikan** (compile error tersembunyi)
- Sekarang dideklarasikan eksplisit sebagai class-level vars di bawah `companion object`

### 3. Bug Startup SplashScreen Diperbaiki  
- Loop `while(true) { withFrameNanos {...} }` tidak pernah berhenti → ANR/freeze di splash
- Dibungkus `try/catch CancellationException` — loop berhenti bersih saat composable di-cancel

### 4. File Hilang dari Hardened Ditambahkan
- `tool/PythonBridgeRunner.kt` — refleksi Chaquopy, mencegah ClassNotFoundException di build tanpa Chaquopy
- `python/alvsia_bridge_impl.py` — bridge dengan auth 64-char token ketat
- `python/alvsia_bridge.py` — auth gate diupgrade ke strict 64-char token check + `import re`
- `python/sealed_loader.py` + `python/sealed/__init__.py` — sealed runtime loader
- `python/lua_engine/luajit_decompiler.py`, `multi_format.py`, `vm_deobfuscator.py`

### 5. Chaquopy Direct Import Dihapus dari ToolEngine
- `import com.chaquo.python.Python` **dihapus** dari `ToolEngine.kt`
- Semua panggilan `Python.isStarted()` / `Python.getInstance()` diganti ke `PythonBridgeRunner`
- Tidak ada lagi `ClassNotFoundException` di build tanpa Chaquopy

### 6. AlvisiaApp Diperbarui
- Beralih dari direct Chaquopy import ke `PythonBridgeRunner.startPlatform()`

### 7. AndroidManifest Diperluas
- Ditambahkan: `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, `REQUEST_INSTALL_PACKAGES`,
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, `RECORD_AUDIO`, `READ_PHONE_STATE`,
  `WAKE_LOCK`, `CHANGE_NETWORK_STATE`
- FileProvider ditambahkan untuk output file sharing
- `android:largeHeap="true"`, `android:extractNativeLibs="true"`

### 8. PermissionHelper Baru
- `sec/PermissionHelper.kt` — fire semua runtime permissions sekaligus saat HomeScreen muncul
- `MANAGE_EXTERNAL_STORAGE` (Android 11+) melalui Settings intent
- `READ_MEDIA_*` untuk Android 13+
- Tidak ada OTP, tidak ada chain dialog — semua izin satu pass

### 9. bridge_run_sub Entry Point Ditambahkan
- `alvsia_bridge.py` dan `alvsia_bridge_impl.py` — tambah `bridge_run_sub()` yang dipanggil oleh `PythonBridgeRunner.runBridge()`

### 10. res/xml/file_paths.xml Ditambahkan
- FileProvider paths untuk akses file hasil kerja tool

### 11. strings.xml Diperbarui
- App name: `ALVSIA PRO` (konsisten)

### 12. FaunaPack Comment Fix
- Komentar "set after OTP loader_key" → "set from panel session on login"

---

## PROTEKSI YANG DIPERTAHANKAN (TIDAK DIUBAH)
- `RaspEngine` — semua 10 detection vector aktif (debugger, Frida, memory dump, root, emulator, clone, integrity, MITM, ADB, hook packages)
- `Guard` — TracerPid + /proc/self/maps hook scan
- `Tamper` — certificate SHA-256 pinning + package name check
- `IntegrityBomb` — multi-signal integrity
- `NativeGuard` — JNI native scan (librasp_guard.so)
- `FridaProbe` — hook package detection
- `MemoryGuard` — ptrace/memory dump detection
- `NetworkGuard` — MITM/proxy detection
- `SessionGate` — session token lock/unlock/wipe
- `ThreatReport` — silent server report untuk setiap threat event
- `Vault` — XOR-obfuscated API endpoints + SPKI certificate pinning
- `sealed_loader.py` — encrypted Python payload loader (aktif di release build)
- R8/ProGuard rules — tidak diubah
- `buildConfigField CERT_SHA256` — tidak diubah

---

## FILE YANG TIDAK ADA (EXPECTED MISSING)
- `sealed/*.alv` — encrypted Python payloads, generated saat release build oleh `tools/seal_python.py`
- `librasp_guard.so` — native RASP library, harus dikompilasi terpisah atau disediakan dari release pipeline
- `.keystore` / signing credentials — tidak disertakan dalam source
- `ALVISIA_R5_4_FINAL_ENGINE.zip` — reference engine, tidak di-merge (hardened reference only)

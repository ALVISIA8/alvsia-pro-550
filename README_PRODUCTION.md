# ALVSIA PRO 5.5.0 — Production Source

**versionName:** `5.5.0-rebrand`  
**versionCode:** `94`  
**applicationId:** `com.alvsia.pro`

## Modules (9)

1. PAK Unpack — extract / list / info / CSV  
2. PAK Rebuild — inject / repack / encrypt / decrypt  
3. PAK Compact — delete entry / empty  
4. OBB Tools — unzip / rezip  
5. LUA Tools — unluac + smart (constants / multi-XOR)  
6. File Scan — strings / hash  
7. Workspace — clear WORK/OUT  
8. Export Report  
9. **Rebrand** — auto ALVSIA PRO / manual brand+channel+watermark  

## Rebrand

**Auto:** select `.lua` or unpacked folder → Auto ALVSIA PRO  

**Manual:** edit `WORK/rebrand_config.txt` on device:

```
brand=ALVSIA PRO
channel=t.me/ALVSIA_PRO
watermark=ALVSIA PRO | t.me/ALVSIA_PRO
```

String replace only. No bot token in PAK/LUA. Panel key/OTP = APK login.

## Engine files

- `app/src/main/python/alvsia_core.py`
- `app/src/main/python/alvsia_features.py`
- `app/src/main/python/alvsia_bridge.py`
- `app/libs/unluac_pro.jar`

## Build

1. `local.properties` → `sdk.dir=/path/to/Android/Sdk`
2. `./gradlew assembleRelease`
3. Sign: see `SIGNING.md` / keystore in root
4. Optional: `codemagic.yaml`

## Requirements

JDK 17 · Android SDK 34 · minSdk 26 · Chaquopy · arm64-v8a

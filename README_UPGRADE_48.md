# ALVSIA PREMIUM TOOL 4.8.0-panelcore

## What changed
- Core fetch cap raised to 12MB (real engine from panel)
- Tool menu aligned to real actions (PAK/Lua/protect)
- coreToolId() maps menu -> panel/core dispatch ids
- Client still: login + OTP + fetch encrypted core only
- No full tool source required in APK assets

## Panel (owner)
1. Upload ALVSIA_TOOL_CORE_LOGIC (Level-A) as Manage Lib name **ALVSIA_CORE**
2. Ensure tool_fetch.php returns encrypted blob after OTP ticket + HWID
3. loader_key.php issues wrap key

## Build
Codemagic / local: ./gradlew assembleRelease
Then ReArk + sign with ALVISIA keystore

## Member gets
Only the APK. Tools run via panel core in RAM after OTP.

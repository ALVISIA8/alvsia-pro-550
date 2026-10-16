# ALVSIA PREMIUM TOOL 4.6

Thin loader APK — **no tool source in assets**.

## Flow
Login → OTP → tool_fetch core into RAM → wipe on exit

## Cloudflare
Skip challenge on `/api/*` while keeping UAM on web pages.

## Panel
Upload encrypted core / RAR to Manage Lib. Password or AES key must come from server after OTP (loader_key), not embedded in APK.

## Build
Android Studio or Codemagic. Then ReArk protect.

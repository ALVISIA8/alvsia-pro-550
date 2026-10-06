#!/data/data/com.termux/files/usr/bin/bash
# ONE-SHOT: align + sign with ALVSIA strong keystore. Run after Codemagic/ReArk APK is on device.
set -e
HOME_TX="${HOME:-/data/data/com.termux/files/home}"
KS="$HOME_TX/ALVISIA_KEYSTORE/alvsia-release.keystore"
if [ ! -f "$KS" ]; then
  KS="$HOME_TX/ALVISIA_PREMIUM_TOOL/alvsia-release.keystore"
fi
if [ ! -f "$KS" ]; then
  echo "[!] keystore not found. Extract ALVISIA_KEYSTORE_STRONG.zip first."
  exit 1
fi
PASS=$(cat "$HOME_TX/ALVISIA_KEYSTORE/STORE_PASSWORD.txt" 2>/dev/null || true)
if [ -z "$PASS" ]; then
  echo "[!] Put password in $HOME_TX/ALVISIA_KEYSTORE/STORE_PASSWORD.txt"
  exit 1
fi
IN="${1:-}"
if [ -z "$IN" ] || [ ! -f "$IN" ]; then
  echo "Usage: $0 /path/to/app-release-or-reark.apk"
  echo "Example: $0 /sdcard/Download/app-release-unsigned.apk"
  exit 1
fi
OUT_DIR="/sdcard/Download"
ALIGNED="$OUT_DIR/alvsia_aligned.apk"
SIGNED="$OUT_DIR/ALVSIA_PREMIUM_TOOL_4.6_SIGNED.apk"
echo "[*] input: $IN"
echo "[*] keystore: $KS"
rm -f "$ALIGNED" "$SIGNED"
if command -v zipalign >/dev/null 2>&1; then
  zipalign -f -p 4 "$IN" "$ALIGNED"
else
  echo "[!] zipalign missing — copy as aligned"
  cp -f "$IN" "$ALIGNED"
fi
apksigner sign \
  --ks "$KS" \
  --ks-key-alias alvsia \
  --ks-pass "pass:$PASS" \
  --key-pass "pass:$PASS" \
  --out "$SIGNED" \
  "$ALIGNED"
apksigner verify -v "$SIGNED" || true
echo "[+] SIGNED: $SIGNED"
echo "[*] Verify cert SHA256 should be: 99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
keytool -printcert -jarfile "$SIGNED" 2>/dev/null | grep -i SHA256 || true

#!/data/data/com.termux/files/usr/bin/bash
# Strict ALVISIA PRO 5.5.0 signing helper for a downloaded release-candidate APK.
# Requires the existing ALVISIA release keystore and Android build-tools in Termux.
set -Eeuo pipefail

HOME_TX="${HOME:-/data/data/com.termux/files/home}"
EXPECTED_CERT="99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
KS="$HOME_TX/ALVISIA_KEYSTORE/alvsia-release.keystore"
if [ ! -f "$KS" ]; then
  KS="$HOME_TX/ALVISIA_KEYSTORE/alvsia-release.jks"
fi
if [ ! -f "$KS" ]; then
  KS="$HOME_TX/ALVISIA_PREMIUM_TOOL/alvsia-release.keystore"
fi
if [ ! -f "$KS" ]; then
  echo "[ERROR] ALVISIA release keystore not found."
  echo "Expected it under: $HOME_TX/ALVISIA_KEYSTORE/"
  exit 1
fi

PASS_FILE="$HOME_TX/ALVISIA_KEYSTORE/STORE_PASSWORD.txt"
PASS="$(cat "$PASS_FILE" 2>/dev/null || true)"
if [ -z "$PASS" ]; then
  echo "[ERROR] Store password file missing or empty: $PASS_FILE"
  echo "Restore it locally from your protected keystore backup; do not send it in chat."
  exit 1
fi

IN="${1:-}"
if [ -z "$IN" ] || [ ! -f "$IN" ]; then
  echo "Usage: $0 /path/to/ALVISIA-PRO-5.5.0-release-candidate.apk"
  exit 2
fi
case "$IN" in
  *.apk) ;;
  *) echo "[ERROR] Input must be an APK file."; exit 2 ;;
esac

for cmd in apksigner zipalign unzip sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[ERROR] Required command not found: $cmd"
    echo "Install/configure Android SDK build-tools in Termux, then retry."
    exit 1
  }
done

OUT_DIR="/storage/emulated/0/Download"
mkdir -p "$OUT_DIR"
ALIGNED="$OUT_DIR/ALVSIA_PRO_5.5.0_aligned.apk"
SIGNED="$OUT_DIR/ALVSIA_PRO_5.5.0_FINAL_SIGNED.apk"
VERIFY="$OUT_DIR/ALVSIA_PRO_5.5.0_FINAL_SIGNED.verify.txt"
SUM="$OUT_DIR/ALVSIA_PRO_5.5.0_FINAL_SIGNED.sha256"

unzip -t "$IN" >/dev/null
echo "[1/5] Input APK archive verified."
echo "[2/5] Aligning APK..."
zipalign -f -p 4 "$IN" "$ALIGNED"

echo "[3/5] Signing with alias alvsia..."
rm -f "$SIGNED" "$VERIFY" "$SUM"
apksigner sign \
  --ks "$KS" \
  --ks-key-alias alvsia \
  --ks-pass "pass:$PASS" \
  --key-pass "pass:$PASS" \
  --out "$SIGNED" \
  "$ALIGNED"

echo "[4/5] Strict signature verification..."
apksigner verify --verbose --print-certs "$SIGNED" 2>&1 | tee "$VERIFY"
ACTUAL_CERT="$(sed -nE 's/.*certificate SHA-256 digest: *([0-9A-Fa-f:]+).*/\1/p' "$VERIFY" | head -n 1 | tr -d ':' | tr 'A-F' 'a-f')"
EXPECTED_LOWER="$(printf '%s' "$EXPECTED_CERT" | tr 'A-F' 'a-f')"
if [ -z "$ACTUAL_CERT" ] || [ "$ACTUAL_CERT" != "$EXPECTED_LOWER" ]; then
  echo "[ERROR] Signing certificate mismatch."
  echo "Expected: $EXPECTED_LOWER"
  echo "Actual:   ${ACTUAL_CERT:-unreadable}"
  rm -f "$SIGNED" "$SUM"
  exit 1
fi

echo "[5/5] Final integrity checks..."
unzip -t "$SIGNED" >/dev/null
sha256sum "$SIGNED" | tee "$SUM"
rm -f "$ALIGNED"
echo
echo "[SUCCESS] Signed APK: $SIGNED"
echo "[SUCCESS] Verify report: $VERIFY"
echo "[SUCCESS] SHA-256 file: $SUM"
echo "Install/test this APK on a device before distributing it."

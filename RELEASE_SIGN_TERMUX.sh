#!/data/data/com.termux/files/usr/bin/bash
# ALVISIA PRO 5.5.0 — align, sign, and strictly verify a release APK.
set -Eeuo pipefail

HOME_TX="${HOME:-/data/data/com.termux/files/home}"
DOWNLOAD="/storage/emulated/0/Download"
EXPECTED_CERT_SHA256="${ALVISIA_CERT_SHA256:-99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c}"
ALIAS="${ALVISIA_KEY_ALIAS:-alvsia}"

IN="${1:-}"
if [[ -z "$IN" || ! -f "$IN" ]]; then
  echo "[ERROR] Input APK not found."
  echo "Usage: bash $0 \"/storage/emulated/0/ALVISIA_PRO_5.5.0_signed(已加固).apk\""
  exit 2
fi

KS="${ALVISIA_KEYSTORE_PATH:-}"
if [[ -z "$KS" ]]; then
  for candidate in \
    "$HOME_TX/ALVISIA_KEYSTORE/alvsia-release.keystore" \
    "$HOME_TX/ALVISIA_KEYSTORE/alvsia-release.jks" \
    "$HOME_TX/ALVISIA_PREMIUM_TOOL/alvsia-release.keystore" \
    "$HOME_TX/ALVISIA_PREMIUM_TOOL/alvsia-release.jks"; do
    if [[ -f "$candidate" ]]; then KS="$candidate"; break; fi
  done
fi
if [[ -z "$KS" || ! -f "$KS" ]]; then
  echo "[ERROR] Keystore not found. Checked ALVISIA_KEYSTORE and ALVISIA_PREMIUM_TOOL."
  exit 3
fi

PASS="${ALVISIA_KEYSTORE_PASSWORD:-}"
if [[ -z "$PASS" ]]; then
  for candidate in \
    "$HOME_TX/ALVISIA_KEYSTORE/STORE_PASSWORD.txt" \
    "$HOME_TX/ALVISIA_PREMIUM_TOOL/STORE_PASSWORD.txt" \
    "$HOME_TX/ALVISIA_KEYSTORE_PASSWORD.txt"; do
    if [[ -s "$candidate" ]]; then PASS="$(cat "$candidate")"; break; fi
  done
fi
if [[ -z "$PASS" ]]; then
  echo "[ERROR] Keystore password missing. Set ALVISIA_KEYSTORE_PASSWORD or STORE_PASSWORD.txt."
  exit 4
fi
KEYPASS="${ALVISIA_KEY_PASSWORD:-$PASS}"

resolve_tool() {
  local name="$1" candidate
  if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return 0; fi
  local prefix="${PREFIX:-/data/data/com.termux/files/usr}"
  for candidate in \
    "$HOME_TX/Android/Sdk/build-tools/"*/"$name" \
    "$HOME_TX/android-sdk/build-tools/"*/"$name" \
    "$prefix/bin/$name"; do
    if [[ -x "$candidate" && ! -d "$candidate" ]]; then echo "$candidate"; return 0; fi
  done
  return 1
}

if ! ZIPALIGN="$(resolve_tool zipalign)"; then
  echo "[ERROR] zipalign not found. Install Android build-tools or add zipalign to PATH."
  exit 5
fi
if ! APKSIGNER="$(resolve_tool apksigner)"; then
  echo "[ERROR] apksigner not found. Install Android build-tools or add apksigner to PATH."
  exit 6
fi

mkdir -p "$DOWNLOAD"
ALIGNED="$DOWNLOAD/ALVISIA_PRO_5.5.0_SIGNING_ALIGNED.apk"
SIGNED="$DOWNLOAD/ALVISIA_PRO_5.5.0_SIGNED.apk"
rm -f "$ALIGNED" "$SIGNED"

echo "[1/4] Input: $IN"
echo "[2/4] Aligning APK..."
"$ZIPALIGN" -f -p 4 "$IN" "$ALIGNED"

echo "[3/4] Signing APK (v2+v3, v1 disabled)..."
"$APKSIGNER" sign \
  --ks "$KS" \
  --ks-key-alias "$ALIAS" \
  --ks-pass "pass:$PASS" \
  --key-pass "pass:$KEYPASS" \
  --v1-signing-enabled false \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$SIGNED" "$ALIGNED"

echo "[4/4] Verifying signature..."
VERIFY="$("$APKSIGNER" verify --verbose --print-certs "$SIGNED")"
printf '%s\n' "$VERIFY"
printf '%s\n' "$VERIFY" | grep -Eqi 'Verified using v1 scheme.*: false' || {
  echo "[ERROR] v1 signing is not disabled as required."; exit 7;
}
printf '%s\n' "$VERIFY" | grep -Eqi 'Verified using v2 scheme.*: true' || {
  echo "[ERROR] v2 signature verification failed."; exit 8;
}
printf '%s\n' "$VERIFY" | grep -Eqi 'Verified using v3 scheme.*: true' || {
  echo "[ERROR] v3 signature verification failed."; exit 9;
}

ACTUAL_CERT_SHA256="$(printf '%s\n' "$VERIFY" | awk -F': ' '/certificate SHA-256 digest/ {print $NF; exit}' | tr -d ':' | tr '[:upper:]' '[:lower:]')"
EXPECTED_CERT_SHA256="$(printf '%s' "$EXPECTED_CERT_SHA256" | tr -d ':' | tr '[:upper:]' '[:lower:]')"
if [[ -z "$ACTUAL_CERT_SHA256" ]]; then
  echo "[ERROR] Could not read signer certificate SHA-256."; exit 10
fi
if [[ "$ACTUAL_CERT_SHA256" != "$EXPECTED_CERT_SHA256" ]]; then
  echo "[ERROR] Certificate mismatch."
  echo "Expected: $EXPECTED_CERT_SHA256"
  echo "Actual:   $ACTUAL_CERT_SHA256"
  exit 11
fi

rm -f "$ALIGNED"
echo "[SUCCESS] Signed and verified: $SIGNED"
ls -lh "$SIGNED"
echo "Certificate SHA-256: $ACTUAL_CERT_SHA256"

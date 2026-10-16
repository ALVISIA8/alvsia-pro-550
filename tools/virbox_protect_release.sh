#!/usr/bin/env bash
# Optional, fail-closed Virbox stage for the ALVISIA release pipeline.
# Requires the licensed vendor CLI and a vendor-generated .ssp profile.
set -euo pipefail

INPUT="${1:?usage: virbox_protect_release.sh INPUT.apk OUTPUT.apk}"
OUTPUT="${2:?usage: virbox_protect_release.sh INPUT.apk OUTPUT.apk}"

if [[ ! -s "$INPUT" ]]; then
  echo "ERROR: input APK is missing or empty: $INPUT" >&2
  exit 2
fi

CLI="${VIRBOX_PROTECTOR_BIN:-}"
PROFILE="${VIRBOX_SSP_FILE:-}"
if [[ -z "$CLI" || ! -x "$CLI" ]]; then
  echo "ERROR: VIRBOX_PROTECTOR_BIN must point to an executable licensed virboxprotector_con." >&2
  exit 3
fi
if [[ -z "$PROFILE" || ! -s "$PROFILE" ]]; then
  echo "ERROR: VIRBOX_SSP_FILE must point to a vendor-generated .ssp profile." >&2
  exit 4
fi

# Virbox reads the matching <input>.ssp profile from the input file's directory.
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
IN_NAME="$(basename "$INPUT")"
WORK_IN="$WORK/$IN_NAME"
WORK_PROFILE="$WORK/$IN_NAME.ssp"
WORK_OUT="$WORK/protected.apk"
cp "$INPUT" "$WORK_IN"
cp "$PROFILE" "$WORK_PROFILE"

"$CLI" "$WORK_IN" -o "$WORK_OUT"
if [[ ! -s "$WORK_OUT" ]]; then
  echo "ERROR: Virbox CLI returned without producing a non-empty APK." >&2
  exit 5
fi
if ! unzip -t "$WORK_OUT" >/dev/null 2>&1; then
  echo "ERROR: Virbox output is not a valid APK/ZIP archive." >&2
  exit 6
fi

mkdir -p "$(dirname "$OUTPUT")"
cp "$WORK_OUT" "$OUTPUT"
echo "VIRBOX_PROTECTION=SUCCESS"
sha256sum "$OUTPUT"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
chmod +x ./gradlew

if [[ "${1:-release}" == "debug" ]]; then
  ./gradlew clean testDebugUnitTest assembleDebug --stacktrace --no-daemon
  exit 0
fi

if [[ -z "${ALVSIA_SEAL_SEED_HEX:-}" ]]; then
  echo "ERROR: generate a fresh 32-byte ALVSIA_SEAL_SEED_HEX in CI." >&2
  exit 2
fi
if [[ ! "$ALVSIA_SEAL_SEED_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: ALVSIA_SEAL_SEED_HEX must contain exactly 64 hexadecimal characters." >&2
  exit 2
fi
export ALVSIA_SEAL_SEED_HEX

restore_python() { python3 tools/seal_python.py --restore >/dev/null 2>&1 || true; }
trap restore_python EXIT

python3 -m compileall -q app/src/main/python
python3 tests/test_lua_engine.py
python3 tests/test_bgmi_transform.py
python3 tests/test_pak_extraction.py
python3 tests/test_tool_dispatch.py
python3 tests/test_vanta_redteam.py
python3 tools/security_release_check.py

python3 -m pip install --disable-pip-version-check cryptography
python3 tools/seal_python.py --restore
python3 tools/seal_python.py --seal
python3 tools/seal_assets.py

./gradlew clean testDebugUnitTest resguardRelease --stacktrace --no-daemon
APK="$(find app/build/outputs/apk/release -maxdepth 1 -type f -name '*.apk' -print -quit)"
test -n "$APK" && test -s "$APK"
unzip -Z1 "$APK" | grep -Fx 'lib/arm64-v8a/librasp_guard.so'
python3 tools/audit_release_apk.py "$APK"
echo "PASS: regression tests and release APK static audit completed."
echo "Production signing is only accepted through the configured CodeMagic main-branch workflow."

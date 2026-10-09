#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$ROOT/app/libs/unluac_pro.jar"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! command -v luac5.3 >/dev/null 2>&1; then
  echo "ERROR: luac5.3 missing; install lua5.3 first" >&2
  exit 2
fi
test -s "$JAR"

cat > "$TMP/source.lua" <<'LUA'
local function add(a, b)
    return a + b
end

local result = add(20, 22)
return result
LUA

luac5.3 -o "$TMP/input.luac" "$TMP/source.lua"
java -cp "$JAR" unluac.Main "$TMP/input.luac" > "$TMP/output.lua" 2> "$TMP/decompiler.stderr"

test -s "$TMP/output.lua"
grep -Eq 'function|local|return' "$TMP/output.lua"
if grep -Eqi '^(Error|Exception|java\.)' "$TMP/output.lua"; then
  echo "ERROR: decompiler emitted an error instead of Lua source" >&2
  cat "$TMP/output.lua" >&2
  exit 1
fi

echo "UNLUAC LUA 5.3 INTEGRATION: PASS"
echo "input_bytes=$(wc -c < "$TMP/input.luac")"
echo "output_bytes=$(wc -c < "$TMP/output.lua")"
head -n 12 "$TMP/output.lua"

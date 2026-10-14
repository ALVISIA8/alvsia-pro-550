#!/usr/bin/env python3
"""Static regression gate for ALVISIA PRO license-only authorization.

This is a source-contract check, not a substitute for live panel/device tests.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main"

def read(rel: str) -> str:
    path = APP / rel
    if not path.is_file():
        raise SystemExit(f"AUTH GATE FAIL: required source missing: {path}")
    return path.read_text(encoding="utf-8", errors="replace")

panel = read("java/com/alvsia/pro/panel/PanelClient.kt")
vault = read("java/com/alvsia/pro/panel/Vault.kt")
crypto = read("java/com/alvsia/pro/panel/Crypto.kt")
activity = read("java/com/alvsia/pro/MainActivity.kt")
session = read("java/com/alvsia/pro/sec/SessionGate.kt")
engine = read("java/com/alvsia/pro/tool/ToolEngine.kt")

checks = {
    "API base targets api.alvsiapro.cc.cd": r'return\s+"https://api\.\$host/api"',
    "TLS pin covers the API subdomain": r'\.add\("\*\.alvsiapro\.cc\.cd",\s*PIN_SPKI\)',
    "captcha.php is the primary handshake endpoint": r'val captchaRaw = openApi\(base\(\) \+ Vault\.pathCaptcha\(\)\)[\s\S]{0,120}?openApi\(base\(\) \+ Vault\.pathG\(\)\)',
    "connect.php is the primary login endpoint": r'var raw2 = postJson\(base\(\) \+ Vault\.pathConnect\(\), loginJson\)[\s\S]{0,200}?raw2 = postJson\(base\(\) \+ Vault\.pathS\(\), loginJson\)'
    "login clears prior session token": r"fun login\s*\([^)]*\)\s*:\s*LoginResult\s*\{[\s\S]{0,500}?sessionToken\s*=\s*\"\"",
    "login consumes panel-issued session_token": r'data\.optString\(\s*"session_token"\s*,\s*""\s*\)',
    "login requires 64-char hexadecimal token": r'issuedToken\.matches\(Regex\("\^\[0-9A-Fa-f\]\{64\}\$"\)\)',
    "fetch binds license to login": r'normalizedLicense\s*!=\s*lastLicense',
    "fetch binds HWID to login": r'normalizedHwid\s*!=\s*lastHwid',
    "fetch requires a valid active token": r'activeToken\.matches\(Regex\("\^\[0-9A-Fa-f\]\{64\}\$"\)\)',
    "fetch sends session_token": r'put\(\s*"session_token"\s*,\s*activeToken\s*\)',
    "app fetches core before secure session unlock": r'panel\.fetchCore\(license,\s*hwid\)[\s\S]{0,12000}?SessionGate\.unlock\(this@MainActivity,\s*token,\s*license\)',
    "failed engine fetch fails closed": r'if\s*\(!engineFromServer\)[\s\S]{0,700}?SessionGate\.lock\(this@MainActivity\)[\s\S]{0,500}?screen\s*=\s*"login"',
    "tool dispatch checks SessionGate": r'SessionGate\.allowTools\(context\)',
    "session gate exposes tool authorization": r'fun\s+allowTools\s*\(',
}
sources = {
    "API base targets api.alvsiapro.cc.cd": vault,
    "TLS pin covers the API subdomain": vault,
    "captcha.php is the primary handshake endpoint": panel,
    "connect.php is the primary login endpoint": panel,
    "login clears prior session token": panel,
    "login consumes panel-issued session_token": panel,
    "login requires 64-char hexadecimal token": panel,
    "fetch binds license to login": panel,
    "fetch binds HWID to login": panel,
    "fetch requires a valid active token": panel,
    "fetch sends session_token": panel,
    "app fetches core before secure session unlock": activity,
    "failed engine fetch fails closed": activity,
    "tool dispatch checks SessionGate": engine,
    "session gate exposes tool authorization": session,
}
failed = []
for label, pattern in checks.items():
    if not re.search(pattern, sources[label]):
        failed.append(label)

for label, source in (("PanelClient.kt", panel), ("Vault.kt", vault), ("Crypto.kt", crypto)):
    if re.search(r"\bAPI[_-]?SECRET\b|api[_-]?secret\s*=", source, re.I):
        failed.append(f"static shared API secret reference found in client auth source: {label}")

for path in APP.rglob("*"):
    if not path.is_file() or path.suffix.lower() not in {".kt", ".java", ".py"}:
        continue
    data = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"\btool_ticket\b|\brequestOtp\b|\bverifyOtp\b|\bOtpScreen\b|\bpathOtp\b", data, re.I):
        failed.append(f"removed client OTP/tool_ticket flow reappeared: {path.relative_to(ROOT)}")

if failed:
    print("AUTH GATE FAIL:")
    for item in failed:
        print(f" - {item}")
    sys.exit(1)

print(f"License-only auth static gate passed ({len(checks)} contract checks); live panel/device testing is still required.")

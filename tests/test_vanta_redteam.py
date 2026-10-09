"""VANTA red-team regression checks for high-impact static findings.

These checks are intentionally conservative and do not claim runtime security.
They guard against regressions in the reviewed source tree.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "app/src/main/python"
ULTIMATE = (PY / "alvsia_ultimate.py").read_text(encoding="utf-8")
CORE = (PY / "alvsia_core.py").read_text(encoding="utf-8")
BRIDGE = (PY / "alvsia_bridge.py").read_text(encoding="utf-8")
GRADLE = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
NATIVE = ROOT / "app/src/main/cpp/rasp_guard.cpp"


def test_no_reported_master_passwords_remain():
    forbidden = ("ALVSIA_2027", "ALVSIA_MASTER_20277")
    source = "\n".join((ULTIMATE, CORE, BRIDGE))
    for secret in forbidden:
        assert secret not in source, f"Hardcoded red-team credential remains: {secret}"


def test_captcha_does_not_use_eval():
    # The challenge must use the constrained parser, not Python eval.
    assert "_safe_captcha_integer(equation)" in ULTIMATE
    assert not re.search(r"(?<![A-Za-z0-9_])eval\s*\(", ULTIMATE), (
        "Unsafe eval() remains in alvsia_ultimate.py"
    )


def test_no_direct_zip_extractall_calls():
    source = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                        for p in ROOT.rglob("*.py") if ".git" not in p.parts)
    assert not re.search(r"\.extractall\s*\(", source), (
        "Direct ZipFile.extractall/ZipFile-like extractall call remains; use validated paths"
    )


def test_release_hardening_is_enabled():
    assert "isMinifyEnabled = true" in GRADLE
    assert "isShrinkResources = true" in GRADLE
    assert "proguard-rules.pro" in GRADLE
    assert "networkSecurityConfig" in MANIFEST
    assert "CERT_SHA256" in GRADLE
    assert NATIVE.is_file(), "Native RASP source is missing"


def test_bridge_requires_apk_session_gate():
    assert 'os.environ.get("ALVSIA_APK_SESSION") != "1"' in BRIDGE


if __name__ == "__main__":
    checks = [
        test_no_reported_master_passwords_remain,
        test_captcha_does_not_use_eval,
        test_no_direct_zip_extractall_calls,
        test_release_hardening_is_enabled,
        test_bridge_requires_apk_session_gate,
    ]
    for check in checks:
        check()
        print("PASS", check.__name__)
    print(f"VANTA STATIC REGRESSION: PASS ({len(checks)}/{len(checks)})")

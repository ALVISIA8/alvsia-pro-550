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
BRIDGE = (PY / "alvsia_bridge.py").read_text(encoding="utf-8") + "\n" + (PY / "alvsia_bridge_impl.py").read_text(encoding="utf-8")
GRADLE = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
NATIVE = ROOT / "app/src/main/cpp/rasp_guard.cpp"
CODEMAGIC = (ROOT / "codemagic.yaml").read_text(encoding="utf-8")
PANEL_CLIENT = (ROOT / "app/src/main/java/com/alvsia/pro/panel/PanelClient.kt").read_text(encoding="utf-8")
MAIN_ACTIVITY = (ROOT / "app/src/main/java/com/alvsia/pro/MainActivity.kt").read_text(encoding="utf-8")
TOOL_ENGINE = (ROOT / "app/src/main/java/com/alvsia/pro/tool/ToolEngine.kt").read_text(encoding="utf-8")
ASSET_VAULT = (ROOT / "app/src/main/java/com/alvsia/pro/asset/AssetVault.kt").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/android-validation.yml").read_text(encoding="utf-8")



def _load_standalone_python_function(name):
    """Load a small stdlib-only function from source without importing the app."""
    import ast
    source_tree = ast.parse(ULTIMATE)
    function = next(
        node for node in source_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {"Path": Path, "os": __import__("os"), "re": re}
    exec(compile(module, str(PY / "alvsia_ultimate.py"), "exec"), namespace)
    return namespace[name]


def test_captcha_parser_accepts_bounded_arithmetic_and_rejects_code():
    solve = _load_standalone_python_function("_safe_captcha_integer")
    assert solve("7 + 5 * 2") == 17
    assert solve("(20 - 8) // 3") == 4
    for malicious in (
        "__import__('os').system('echo unsafe')",
        "open('/tmp/alvsia-test', 'w')",
        "1 / 0",
        "9 ** 99",
        "1" * 300,
    ):
        try:
            solve(malicious)
        except (ValueError, SyntaxError, ZeroDivisionError):
            pass
        else:
            raise AssertionError(f"Captcha parser accepted invalid input: {malicious!r}")


def test_zip_extractor_rejects_path_traversal():
    import tempfile
    import zipfile
    extract = _load_standalone_python_function("_alvsia_safe_extract_zip")
    with tempfile.TemporaryDirectory(prefix="alvsia-vanta-") as temp:
        tmp_path = Path(temp)
        archive_path = tmp_path / "malicious.zip"
        output = tmp_path / "out"
        outside = tmp_path / "escape.txt"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../escape.txt", "must-not-write")
        with zipfile.ZipFile(archive_path) as archive:
            try:
                extract(archive, output)
            except ValueError as exc:
                assert "Unsafe ZIP entry path rejected" in str(exc)
            else:
                raise AssertionError("ZIP traversal entry was not rejected")
        assert not outside.exists(), "ZIP traversal wrote outside destination"


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
                        for p in PY.rglob("*.py"))
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


def test_release_tls_pinning_fails_closed():
    assert "if (BuildConfig.DEBUG)" in PANEL_CLIENT
    assert "clientLoose.newCall(req).execute()" in PANEL_CLIENT
    assert "BLOCKED: TLS pin verification failed" in PANEL_CLIENT
    assert "_pinGrace" not in PANEL_CLIENT


def test_release_seals_asset_jars_and_disables_plaintext_fallback():
    assert "AssetVault.materializeJars(context, jarsDir)" in TOOL_ENGINE
    assert "if (!BuildConfig.DEBUG) return" in TOOL_ENGINE
    assert "dest.writeBytes(bytes)" in ASSET_VAULT
    assert "bytes.fill(0)" in ASSET_VAULT
    assert "tools/seal_assets.py" in CODEMAGIC
    assert "tools/seal_assets.py" in WORKFLOW


def test_otp_enforces_rasp_before_engine_fetch():
    # A successful OTP response must not bypass the hostile-environment gate.
    otp = MAIN_ACTIVITY.find("val safeAfterOtp")
    fetch = MAIN_ACTIVITY.find("panel.fetchCore(license, hwid, res.toolTicket)")
    assert otp >= 0 and fetch > otp, "RASP gate must run before protected engine fetch"
    gate = MAIN_ACTIVITY[otp:fetch]
    assert "Guard.checkAndReport(" in gate
    assert "if (!safeAfterOtp)" in gate
    assert "SessionGate.lock(this@MainActivity)" in gate



def test_otp_fails_closed_when_panel_engine_is_missing():
    # A valid OTP alone must not enable bundled fallback tools when the protected
    # engine fetch fails; the panel-provided engine is required for this session.
    fetch = MAIN_ACTIVITY.find("panel.fetchCore(license, hwid, res.toolTicket)")
    tamper = MAIN_ACTIVITY.find("val tamper = Tamper.evaluate", fetch)
    assert fetch >= 0 and tamper > fetch
    block = MAIN_ACTIVITY[fetch:tamper]
    assert "if (!engineFromServer)" in block
    assert "SessionGate.lock(this@MainActivity)" in block
    assert "engine.wipeEngine()" in block
    assert "return@launch" in block
    assert "FaunaPack.unpackFromAssets" not in MAIN_ACTIVITY

def test_apk_session_requires_native_token_shape():
    import os
    from unittest.mock import patch
    valid = _load_standalone_python_function("_alv_apk_session_valid")
    with patch.dict(os.environ, {"ALVSIA_APK_SESSION": "1"}, clear=False):
        os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        assert not valid(), "Session marker alone must not authorize the Python engine"
        os.environ["ALVSIA_SESSION_TOKEN"] = "not-a-token"
        assert not valid(), "Malformed session token must be rejected"
        os.environ["ALVSIA_SESSION_TOKEN"] = "a" * 64
        assert valid(), "A 64-hex token from the native gate should pass shape validation"
    assert "if _alvsia_core_apk_session_valid():" in CORE
    assert "if _alv_apk_session_valid():" in ULTIMATE
    assert "if not _valid_apk_session():" in BRIDGE



def test_core_operation_gate_rejects_marker_only_bypass():
    import ast
    import os
    from unittest.mock import patch

    tree = ast.parse(CORE)
    names = {"_alvsia_core_apk_session_valid", "_alvsia_require_operation"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    namespace = {"_ALVSIA_CORE_ACTIVE_PROOF": None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(PY / "alvsia_core.py"), "exec"), namespace)
    require = namespace["_alvsia_require_operation"]

    with patch.dict(os.environ, {"ALVSIA_APK_SESSION": "1"}, clear=False):
        os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        try:
            require({"pak_unpack"})
        except RuntimeError as exc:
            assert "authorization failed" in str(exc).lower()
        else:
            raise AssertionError("Core accepted APK session marker without token")
        os.environ["ALVSIA_SESSION_TOKEN"] = "malformed"
        try:
            require({"pak_unpack"})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Core accepted malformed APK session token")
        os.environ["ALVSIA_SESSION_TOKEN"] = "a" * 64
        assert require({"pak_unpack"}) is True

def test_bridge_requires_apk_session_gate():
    assert "if not _valid_apk_session():" in BRIDGE
    assert "ALVSIA_SESSION_TOKEN" in BRIDGE



def test_external_data_downloads_are_commit_pinned_and_integrity_checked():
    # These data downloads are pinned to immutable Git commits and checked against
    # the upstream Git blob ID/size before the downloaded file is accepted.
    assert "/SKIN_TOOL/main/SKIN_TOOL.zip" not in ULTIMATE
    assert "/BGMI_CSV/main/PUBG.csv" not in ULTIMATE
    assert "/BGMI_CSV/main/BGMI.csv" not in ULTIMATE
    assert "5c7ad2b4996fcd468bf245be43580d1fe131423e" in ULTIMATE
    assert "d013eca408f85d073c195e42a363b49076babd1d" in ULTIMATE
    assert "_verify_pinned_git_blob" in ULTIMATE
    assert "cbd3d0e257963b54f34a908b6864040c7f96fbb1" in ULTIMATE
    assert "2601457787bd2d793880fb1a8c485d0e76144942" in ULTIMATE
    assert "ac72bf1d3ca5f0ae72b65c1845c9c471e4a4a6af" in ULTIMATE


def test_codemagic_release_signing_fails_closed_and_pins_certificate():
    sign_block = CODEMAGIC.split("- name: Sign and verify production release APK", 1)[1]
    assert 'if [ -z "${CM_KEYSTORE:-}" ] || [ -z "${CM_KEYSTORE_PASSWORD:-}" ]; then' in sign_block
    assert 'exit 2' in sign_block
    assert 'apksigner" verify --verbose --print-certs' in sign_block
    assert '99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c' in sign_block
    assert 'ALVSIA_PRO_5.5.0_unsigned.apk' not in CODEMAGIC
    assert 'app/build/outputs/apk/**/*.apk' not in CODEMAGIC
    assert 'groups:\n        - signing' in CODEMAGIC
    assert '- name: Check release signing secrets' in CODEMAGIC


if __name__ == "__main__":
    checks = [
        test_captcha_parser_accepts_bounded_arithmetic_and_rejects_code,
        test_zip_extractor_rejects_path_traversal,
        test_no_reported_master_passwords_remain,
        test_captcha_does_not_use_eval,
        test_no_direct_zip_extractall_calls,
        test_release_hardening_is_enabled,
        test_release_tls_pinning_fails_closed,
        test_release_seals_asset_jars_and_disables_plaintext_fallback,
        test_otp_enforces_rasp_before_engine_fetch,
        test_otp_fails_closed_when_panel_engine_is_missing,
        test_apk_session_requires_native_token_shape,
        test_core_operation_gate_rejects_marker_only_bypass,
        test_bridge_requires_apk_session_gate,
        test_external_data_downloads_are_commit_pinned_and_integrity_checked,
        test_codemagic_release_signing_fails_closed_and_pins_certificate,
    ]
    for check in checks:
        check()
        print("PASS", check.__name__)
    print(f"VANTA STATIC REGRESSION: PASS ({len(checks)}/{len(checks)})")

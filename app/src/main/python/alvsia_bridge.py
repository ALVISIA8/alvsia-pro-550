# -*- coding: utf-8 -*-
"""Minimal Chaquopy entry point; tool routing is loaded from the sealed implementation."""
from __future__ import annotations

import os
import re


def _session_gate():
    from com.alvsia.pro.sec import SessionGate
    return SessionGate


def _authorized() -> bool:
    try:
        gate = _session_gate()
        return bool(gate.isSessionAuthorized())
    except Exception:
        return False


def _install_sealed_runtime() -> None:
    if os.environ.get("ALVSIA_SEALED_RUNTIME") != "1" or not _authorized():
        return
    try:
        import pkgutil
        if pkgutil.get_data("sealed", "alvsia_bridge_impl.alv") is not None:
            import sealed_loader
            sealed_loader.install()
    except (ImportError, FileNotFoundError, RuntimeError, TypeError):
        # Debug/test builds may intentionally have no generated sealed payloads.
        pass


def configure_runtime(token, sealed_runtime="1"):
    """Verify the supplied token against Kotlin's live SessionGate; never store it in Python."""
    if not isinstance(token, str) or re.fullmatch(r"[0-9A-Fa-f]{64}", token) is None:
        return False
    try:
        gate = _session_gate()
        if not bool(gate.isTokenCurrent(token)):
            return False
    except Exception:
        return False

    os.environ.pop("ALVSIA_SESSION_TOKEN", None)
    os.environ["ALVSIA_APK_SESSION"] = "1"
    os.environ["ALVSIA_SEALED_RUNTIME"] = "1" if str(sealed_runtime) == "1" else "0"
    _install_sealed_runtime()
    return True


def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    if not _authorized() or os.environ.get("ALVSIA_APK_SESSION") != "1":
        return "X AUTH: no valid Kotlin APK session — login with your key first"
    _install_sealed_runtime()
    try:
        import alvsia_bridge_impl as impl
        return impl.run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir)
    except Exception as exc:
        return "X SEALED BRIDGE: %s" % (str(exc) or type(exc).__name__)


def bridge_run_sub(module_id, sub_id, input_path, extra_name, work_dir_path, jars_dir_path):
    return run_tool(
        int(module_id),
        str(sub_id),
        str(input_path) if input_path else "",
        str(work_dir_path),
        str(jars_dir_path),
        str(jars_dir_path),
    )

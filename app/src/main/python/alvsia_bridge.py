# -*- coding: utf-8 -*-
"""Small bootstrap for the sealed ALVISIA PRO tool dispatcher."""
from __future__ import annotations
import os
import re

def _valid_apk_session() -> bool:
    token = os.environ.get("ALVSIA_SESSION_TOKEN", "")
    return (
        os.environ.get("ALVSIA_APK_SESSION") == "1"
        and re.fullmatch(r"[0-9A-Fa-f]{64}", token) is not None
    )

def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    if not _valid_apk_session():
        return "X AUTH: no valid APK session — complete license + OTP first"
    if os.environ.get("ALVSIA_SEALED_RUNTIME") == "1":
        try:
            import sealed_loader
            sealed_loader.install()
        except Exception as exc:
            return "X AUTH: sealed runtime unavailable: %s" % exc
    try:
        import alvsia_bridge_impl
        return alvsia_bridge_impl.run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir)
    except Exception as exc:
        return "X BRIDGE BOOTSTRAP ERROR: %s" % exc

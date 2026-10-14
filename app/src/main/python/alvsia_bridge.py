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
        return "X AUTH: no valid APK session — sign in with a valid panel license"
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


def bridge_run_sub(module_id, sub_id, input_path, extra_name, work_dir_path, jars_dir_path):
    """Compatibility entry point expected by PythonBridgeRunner in the Android app."""
    work_root = str(work_dir_path or extra_name or "")
    if not work_root:
        return "X BRIDGE: workspace path missing"
    return run_tool(module_id, sub_id, input_path, work_root, work_root, jars_dir_path)

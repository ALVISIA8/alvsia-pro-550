import os
import re

def _authorized():
    try:
        from com.alvsia.pro.sec import SessionGate
        return bool(SessionGate.isSessionAuthorized())
    except Exception:
        return False

def _install_sealed_runtime():
    if os.environ.get("ALVSIA_SEALED_RUNTIME") != "1" or not _authorized():
        return
    try:
        import pkgutil
        if pkgutil.get_data("sealed", "alvsia_bridge_impl.alv") is not None:
            import sealed_loader
            sealed_loader.install()
    except Exception:
        pass

def _extract_str(val) -> str:
    """Safely extract a plain Python str from a value that may be a
    Chaquopy PyObject wrapping a Java String, a plain Python str, or
    anything else.  Chaquopy's PyObject.__str__() returns the Java
    String's value, so str() is correct — but we defend against edge
    cases where repr() leaks (e.g. a proxy object whose __str__ has
    been overridden by a buggy Chaquopy version)."""
    if isinstance(val, str):
        return val.strip()
    raw = str(val).strip()
    # Guard against Chaquopy repr leakage like "java.lang.String@..."
    if raw.startswith("java.") or raw.startswith("com.chaquo."):
        # Try __str__ directly on the underlying Java object if available.
        try:
            return val.__str__().strip()
        except Exception:
            return ""
    return raw


def configure_runtime(token, sealed_runtime="1"):
    try:
        token = _extract_str(token)
        if re.fullmatch(r"[0-9A-Fa-f]{64}", token) is None:
            return False
        from com.alvsia.pro.sec import SessionGate
        gate = SessionGate
        # Pass the plain Python str (not the original PyObject) to isTokenCurrent
        # so Chaquopy performs a clean Java-String conversion.
        if not bool(gate.isTokenCurrent(token)):
            return False
        os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        os.environ["ALVSIA_APK_SESSION"] = "1"
        os.environ["ALVSIA_SEALED_RUNTIME"] = "1" if _extract_str(sealed_runtime) == "1" else "0"
        _install_sealed_runtime()
        # Return the Python literal True so Chaquopy renders it as "True" via
        # PyObject.toString().  Do NOT return a Java Boolean — Kotlin's receiver
        # uses configure?.toString() != "True" as the contract check.
        return True
    except Exception:
        return False

def run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir):
    if not _authorized() or os.environ.get("ALVSIA_APK_SESSION") != "1":
        return "X AUTH: login required"
    _install_sealed_runtime()
    try:
        import alvsia_bridge_impl as impl
        return impl.run_tool(module_id, sub_id, input_path, out_root, engine_dir, jars_dir)
    except Exception as exc:
        return "X SEALED BRIDGE: %s" % (str(exc) or type(exc).__name__)

def bridge_run_sub(module_id, sub_id, input_path, extra_name, work_dir_path, jars_dir_path):
    return run_tool(int(module_id), str(sub_id), str(input_path) if input_path else "",
                    str(work_dir_path), str(jars_dir_path), str(jars_dir_path))

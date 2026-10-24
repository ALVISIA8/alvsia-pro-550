import os, re

def _authorized():
    try:
        from com.alvsia.pro.sec import SessionGate
        return bool(SessionGate.isSessionAuthorized())
    except Exception:
        return False

def _isr():
    if os.environ.get("ALVSIA_SEALED_RUNTIME") != "1" or not _authorized():
        return
    try:
        import pkgutil
        if pkgutil.get_data("sealed", "alvsia_bridge_impl.alv"):
            import sealed_loader
            sealed_loader.install()
    except Exception:
        pass

def _extract_str(val):
    if isinstance(val, str):
        return val.strip()
    raw = str(val).strip()
    if raw.startswith(("java.", "com.chaquo.")):
        try:
            return val.__str__().strip()
        except Exception:
            return ""
    return raw

def configure_runtime(token, sealed_runtime="1"):
    try:
        token = _extract_str(token)
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", token):
            return False
        from com.alvsia.pro.sec import SessionGate
        gate = SessionGate
        if not bool(gate.isTokenCurrent(token)):
            return False
        os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        os.environ["ALVSIA_APK_SESSION"] = "1"
        os.environ["ALVSIA_SEALED_RUNTIME"] = "1" if _extract_str(sealed_runtime) == "1" else "0"
        _isr()
        return True  # literal True; Kotlin contract: toString() == "True"
    except Exception:
        return False

def run_tool(mid, sid, inp, out_root, engine_dir, jars_dir):
    if not _authorized() or os.environ.get("ALVSIA_APK_SESSION") != "1":
        return "X AUTH: login required"
    _isr()
    try:
        import alvsia_bridge_impl as impl
        return impl.run_tool(mid, sid, inp, out_root, engine_dir, jars_dir)
    except Exception as exc:
        return "X SEALED BRIDGE: %s" % (str(exc) or type(exc).__name__)

def bridge_run_sub(mid, sid, inp, en, wd, jd):
    return run_tool(int(mid), str(sid), str(inp) if inp else "", str(wd), str(jd), str(jd))

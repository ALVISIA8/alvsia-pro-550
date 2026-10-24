import os, re
def _authorized():
    try:
        from com.alvsia.pro.sec import SessionGate
        return bool(SessionGate.isSessionAuthorized())
    except Exception: return False
def _isr():
    if os.environ.get("ALVSIA_SEALED_RUNTIME") != "1" or not _authorized(): return
    try:
        import pkgutil
        if pkgutil.get_data("sealed", "alvsia_bridge_impl.alv"):
            import sealed_loader
            sealed_loader.install()
    except Exception: pass
_CD = "not called"
def configure_diagnostic(): return _CD
def configure_runtime(token, sealed_runtime="1"):
    global _CD
    try:
        token = str(token).strip()
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", token):
            _CD = "bad_token"; return False
        from com.alvsia.pro.sec import SessionGate
        if not bool(SessionGate.isSessionAuthorized()):
            _CD = "gate_unauthorized"; return False
        if not bool(SessionGate.isTokenCurrent(token)):
            _CD = "token_mismatch_or_expired"; return False
        os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        os.environ["ALVSIA_APK_SESSION"] = "1"
        os.environ["ALVSIA_SEALED_RUNTIME"] = "1" if str(sealed_runtime).strip() == "1" else "0"
        _isr(); _CD = "ok"; return True
    except Exception:
        _CD = "configure_exception"; return False
def run_tool(mid, sid, inp, out_root, engine_dir, jars_dir):
    if not _authorized() or os.environ.get("ALVSIA_APK_SESSION") != "1": return "X AUTH: login required"
    _isr()
    try:
        import alvsia_bridge_impl as impl
        return impl.run_tool(mid, sid, inp, out_root, engine_dir, jars_dir)
    except Exception as exc: return "X SEALED BRIDGE: %s" % (str(exc) or type(exc).__name__)
def bridge_run_sub(mid, sid, inp, en, wd, jd):
    return run_tool(int(mid), str(sid), str(inp) if inp else "", str(wd), str(jd), str(jd))

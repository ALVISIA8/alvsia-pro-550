import os,re
def _authorized():
    try:
        from com.alvsia.pro.sec import SessionGate
        return bool(SessionGate.isSessionAuthorized())
    except Exception: return False
def _install_sealed_runtime():
    if os.environ.get("ALVSIA_SEALED_RUNTIME")!="1" or not _authorized(): return
    try:
        import pkgutil
        if pkgutil.get_data("sealed","alvsia_bridge_impl.alv") is not None:
            import sealed_loader
            sealed_loader.install()
    except Exception: pass
def _extract_str(v):
    try:
        s=(v if isinstance(v,str) else str(v)).strip()
        if s.startswith(("java.","com.chaquo.")):
            try: s=v.__str__().strip()
            except Exception: return ""
        return s
    except Exception: return ""
def configure_runtime(token,sealed_runtime="1"):
    try:
        token=_extract_str(token)
        if re.fullmatch(r"[0-9A-Fa-f]{64}",token) is None: return False
        from com.alvsia.pro.sec import SessionGate
        if not bool(SessionGate.isTokenCurrent(token)): return False
        os.environ.pop("ALVSIA_SESSION_TOKEN",None)
        os.environ["ALVSIA_APK_SESSION"]="1"
        os.environ["ALVSIA_SEALED_RUNTIME"]="1" if _extract_str(sealed_runtime)=="1" else "0"
        _install_sealed_runtime()
        return True
    except Exception: return False
def run_tool(module_id,sub_id,input_path,out_root,engine_dir,jars_dir):
    if not _authorized() or os.environ.get("ALVSIA_APK_SESSION")!="1": return "X AUTH: login required"
    _install_sealed_runtime()
    try:
        import alvsia_bridge_impl as impl
        return impl.run_tool(module_id,sub_id,input_path,out_root,engine_dir,jars_dir)
    except Exception as exc: return "X SEALED BRIDGE: %s"%(str(exc) or type(exc).__name__)
def bridge_run_sub(module_id,sub_id,input_path,extra_name,work_dir_path,jars_dir_path):
    return run_tool(int(module_id),str(sub_id),str(input_path) if input_path else "",str(work_dir_path),str(jars_dir_path),str(jars_dir_path))

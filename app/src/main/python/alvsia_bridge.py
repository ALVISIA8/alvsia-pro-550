import os,re
_DIAG="not_called"
def _authorized():
 try:
  from com.alvsia.pro.sec import SessionGate
  return bool(SessionGate.isSessionAuthorized())
 except Exception as e:
  return False
def _install_sealed_runtime():
 if os.environ.get("ALVSIA_SEALED_RUNTIME")!="1" or not _authorized(): return
 try:
  import pkgutil
  if pkgutil.get_data("sealed","alvsia_bridge_impl.alv") is not None:
   import sealed_loader
   sealed_loader.install()
 except Exception: pass
def configure_runtime(token,sealed_runtime="1"):
 global _DIAG
 try:
  token=str(token).strip()
  if re.fullmatch(r"[0-9A-Fa-f]{64}",token) is None:
   _DIAG="token_shape"; return False
  from com.alvsia.pro.sec import SessionGate
  if not bool(SessionGate.isTokenCurrent(token)):
   _DIAG="session_gate_rejected"; return False
  os.environ.pop("ALVSIA_SESSION_TOKEN",None)
  os.environ["ALVSIA_APK_SESSION"]="1"
  os.environ["ALVSIA_SEALED_RUNTIME"]="1" if str(sealed_runtime)=="1" else "0"
  _install_sealed_runtime()
  _DIAG="accepted"
  return True
 except Exception as e:
  _DIAG="exception:"+type(e).__name__
  return False
def runtime_diagnostic():
 return _DIAG
def run_tool(module_id,sub_id,input_path,out_root,engine_dir,jars_dir):
 if not _authorized() or os.environ.get("ALVSIA_APK_SESSION")!="1":
  return "X AUTH: login required"
 _install_sealed_runtime()
 try:
  import alvsia_bridge_impl as impl
  return impl.run_tool(module_id,sub_id,input_path,out_root,engine_dir,jars_dir)
 except Exception as e:
  return "X SEALED BRIDGE: %s"%(str(e) or type(e).__name__)
def bridge_run_sub(module_id,sub_id,input_path,extra_name,work_dir_path,jars_dir_path):
 return run_tool(int(module_id),str(sub_id),str(input_path) if input_path else "",str(work_dir_path),str(jars_dir_path),str(jars_dir_path))

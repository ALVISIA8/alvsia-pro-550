import os,re
def _authorized():
 try:
  from com.alvsia.pro.sec import SessionGate
  return bool(SessionGate.isSessionAuthorized())
 except Exception:return False
def _isr():
 if os.environ.get("ALVSIA_SEALED_RUNTIME")!="1" or not _authorized():return
 try:
  import pkgutil
  if pkgutil.get_data("sealed","alvsia_bridge_impl.alv"):
   import sealed_loader
   sealed_loader.install()
 except Exception:pass
_CD=""
def configure_diagnostic():return _CD
def _s(v):
 if isinstance(v,str):return v
 try:return str(v.toString())
 except Exception:return str(v)
def configure_runtime(token,sealed_runtime="1"):
 global _CD
 stage="token_normalize"
 try:
  token=_s(token).strip()
  if not re.fullmatch(r"[0-9A-Fa-f]{64}",token):_CD="bad_token";return False
  stage="session_gate_import"
  from com.alvsia.pro.sec import SessionGate
  stage="session_token_check"
  if not bool(SessionGate.isTokenCurrent(token)):_CD="gate_reject";return False
  stage="runtime_setup"
  os.environ.pop("ALVSIA_SESSION_TOKEN",None)
  os.environ["ALVSIA_APK_SESSION"]="1"
  os.environ["ALVSIA_SEALED_RUNTIME"]="1" if _s(sealed_runtime).strip()=="1" else "0"
  stage="sealed_runtime_install"
  _isr();_CD="ok";return True
 except Exception as e:
  m=re.sub(r"[^A-Za-z0-9_.-]","",str(getattr(e,"name","") or ""))[:80]
  d=re.sub(r"[^A-Za-z0-9_.:/ -]","?",str(e or ""))[:100].strip()
  _CD="config_exc:"+stage+":"+type(e).__name__+(":module="+m if m else "")+(":detail="+d if d else "")
  return False
def run_tool(mid,sid,inp,out_root,engine_dir,jars_dir):
 if not _authorized() or os.environ.get("ALVSIA_APK_SESSION")!="1":return "X AUTH: login required"
 _isr()
 try:
  import alvsia_bridge_impl as impl
  return impl.run_tool(mid,sid,inp,out_root,engine_dir,jars_dir)
 except Exception as e:return "X SEALED BRIDGE: %s"%(str(e) or type(e).__name__)
def bridge_run_sub(mid,sid,inp,en,wd,jd):
 return run_tool(int(mid),str(sid),str(inp) if inp else "",str(wd),str(jd),str(jd))

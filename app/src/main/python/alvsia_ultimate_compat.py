# -*- coding: utf-8 -*-
"""ALVISIA R5.4 Ultimate API compatibility layer.

This module supplies the exact 31 callables used by alvsia_bridge when the
sealed alvsia_ultimate module does not expose a legacy API name.  It is an
adapter, not a replacement for the sealed engine: operations delegate to
alvsia_features/alvsia_core where possible and perform conservative local
analysis for the remaining APIs.
"""
from __future__ import annotations

import hashlib, json, math, os, re, shutil, struct, subprocess, zipfile
from pathlib import Path
from typing import Any


def _p(x): return Path(str(x))
def _out(d, name):
    p=_p(d); p.mkdir(parents=True, exist_ok=True); return p/name

def _result(ok=True, **kw):
    r={'ok': bool(ok)}; r.update(kw); return r

def _bytes(path): return _p(path).read_bytes()

def _ascii_strings(data, n=4):
    out=[]; cur=[]
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur)>=n: out.append(bytes(cur).decode('ascii','ignore'))
            cur=[]
    if len(cur)>=n: out.append(bytes(cur).decode('ascii','ignore'))
    return out

def _entropy(data):
    if not data: return 0.0
    freq=[0]*256
    for b in data: freq[b]+=1
    n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def _safe_name(s): return re.sub(r'[^A-Za-z0-9_.-]+','_',str(s))[:100]

def _write_json(outdir, stem, obj):
    p=_out(outdir, stem+'.json'); p.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8'); return str(p)

def _file_audit(path, outdir, kind):
    p=_p(path); data=p.read_bytes(); strings=_ascii_strings(data)
    urls=[s for s in strings if re.match(r'^(?:https?|wss?|tcp)://',s,re.I)]
    report={'kind':kind,'file':p.name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'entropy':round(_entropy(data),4),'strings':len(strings),'urls':urls[:200]}
    if data[:4]==b'PK\x03\x04':
        try:
            with zipfile.ZipFile(p) as z: report['zip_entries']=len(z.infolist())
        except Exception as e: report['zip_error']=str(e)
    if kind=='apk':
        report['apk_markers']={k:(k.encode() in data) for k in ('classes.dex','AndroidManifest.xml','resources.arsc','META-INF')}
    elif kind=='so':
        report['elf_magic']=data[:4]==b'\x7fELF'; report['elf_class']=data[4] if len(data)>4 and data[:4]==b'\x7fELF' else None
    elif kind=='lua':
        report['lua_magic']=data[:4]==b'\x1bLua'; report['luajit_magic']=data[:3]==b'\x1bLJ'
    return _result(True, msg='audit complete', out=_write_json(outdir,p.stem,report), report=report)

# --- audits ---------------------------------------------------------------
def audit_apk(path, outdir): return _file_audit(path,outdir,'apk')
def audit_lua(path, outdir): return _file_audit(path,outdir,'lua')
def audit_so(path, outdir): return _file_audit(path,outdir,'so')

# --- crypto helpers -------------------------------------------------------
def _cfg(workdir):
    p=_p(workdir)
    vals={}
    for name in ('decrypt_config.json','crypto.json','aes.json'):
        f=p/name
        if f.is_file():
            try: vals.update(json.loads(f.read_text(encoding='utf-8')))
            except Exception: pass
    return vals

def _hex_or_text(v):
    if v is None: return None
    s=str(v).strip()
    try:
        if len(s)%2==0 and re.fullmatch(r'[0-9a-fA-F]+',s): return bytes.fromhex(s)
    except Exception: pass
    return s.encode()

def decrypt_aes(path, outdir, workdir, mode='CBC'):
    cfg=_cfg(workdir); key=_hex_or_text(cfg.get('key')); iv=_hex_or_text(cfg.get('iv',b'\0'*16)) or b'\0'*16
    if not key: return _result(False,msg='AES key missing: create WORK/decrypt_config.json with key and optional iv')
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except Exception as e: return _result(False,msg='PyCryptodome unavailable: '+str(e))
    data=_bytes(path)
    if len(data)%16: return _result(False,msg='AES ciphertext size is not block aligned')
    try:
        cipher=AES.new(key, AES.MODE_ECB if str(mode).upper()=='ECB' else AES.MODE_CBC, None if str(mode).upper()=='ECB' else iv[:16])
        plain=cipher.decrypt(data)
        try: plain=unpad(plain,16)
        except Exception: pass
        out=_out(outdir,_p(path).stem+'_dec'+_p(path).suffix); out.write_bytes(plain)
        return _result(True,msg='AES decrypt complete',out=str(out),bytes=len(plain))
    except Exception as e: return _result(False,msg='AES decrypt failed: '+str(e))

def decrypt_simple1(path, outdir):
    data=_bytes(path); plain=bytes(b ^ 121 for b in data)
    out=_out(outdir,_p(path).stem+'_dec'+_p(path).suffix); out.write_bytes(plain)
    return _result(True,msg='Simple1 XOR decrypt complete',out=str(out),bytes=len(plain))

def decrypt_sm4(path, outdir, workdir):
    # Prefer the same SM4 implementation used by the reference engine if it
    # is available in the runtime; otherwise fail explicitly instead of
    # silently producing a bogus output.
    cfg=_cfg(workdir); key=_hex_or_text(cfg.get('key'))
    if not key: return _result(False,msg='SM4 key missing: create WORK/decrypt_config.json with key')
    try:
        import gmalg  # some Android builds expose SM4 through this package
        if hasattr(gmalg,'SM4'):
            sm4=gmalg.SM4(key[:16]); data=_bytes(path); plain=sm4.decrypt(data)
            out=_out(outdir,_p(path).stem+'_dec'+_p(path).suffix); out.write_bytes(plain)
            return _result(True,msg='SM4 decrypt complete',out=str(out))
    except Exception as e:
        return _result(False,msg='SM4 backend unavailable: '+str(e))
    return _result(False,msg='SM4 backend unavailable; no output written')

def decrypt_zuc(path, outdir, workdir):
    cfg=_cfg(workdir); key=_hex_or_text(cfg.get('key')); iv=_hex_or_text(cfg.get('iv'))
    if not key or not iv: return _result(False,msg='ZUC key/iv missing: create WORK/decrypt_config.json')
    try:
        import gmalg
        zuc=gmalg.ZUC(key[:16],iv[:16]); data=_bytes(path); ks=b''.join(zuc.generate() for _ in range((len(data)+3)//4))[:len(data)]
        plain=bytes(a^b for a,b in zip(data,ks)); out=_out(outdir,_p(path).stem+'_dec'+_p(path).suffix); out.write_bytes(plain)
        return _result(True,msg='ZUC decrypt complete',out=str(out))
    except Exception as e: return _result(False,msg='ZUC backend unavailable or invalid key/iv: '+str(e))

def decrypt_auto(path, outdir, workdir):
    p=_p(path); data=p.read_bytes();
    if data[:4]==b'PK\x03\x04': return _result(False,msg='Input is already a ZIP/OBB container')
    cfg=_cfg(workdir)
    if cfg.get('cipher'):
        c=str(cfg['cipher']).lower()
        if c=='simple1': return decrypt_simple1(path,outdir)
        if c=='aes': return decrypt_aes(path,outdir,workdir,cfg.get('mode','CBC'))
        if c=='sm4': return decrypt_sm4(path,outdir,workdir)
        if c=='zuc': return decrypt_zuc(path,outdir,workdir)
    # Conservative auto-detection: only Simple1 is deterministic and keyless.
    # Do not guess AES/SM4/ZUC keys.
    return _result(False,msg='No explicit cipher config. Set WORK/decrypt_config.json')

# --- SO analysis ----------------------------------------------------------
def so_xor_brute(path,outdir):
    data=_bytes(path); hits=[]
    for k in range(1,256):
        x=bytes(b^k for b in data[:min(len(data),65536)])
        if x[:4]==b'\x7fELF': hits.append({'key':k,'type':'ELF'})
    p=_out(outdir,'xor_candidates.json'); p.write_text(json.dumps(hits,indent=2),encoding='utf-8')
    return _result(True,msg=f'{len(hits)} candidates',out=str(p),candidates=hits)

def so_multi_xor(path,outdir,custom_keys=None):
    data=_bytes(path); keys=custom_keys or [bytes([k]) for k in range(1,256)]
    hits=[]
    for key in keys:
        if not key: continue
        x=bytes(b^key[i%len(key)] for i,b in enumerate(data[:65536]))
        if x[:4]==b'\x7fELF': hits.append({'key':bytes(key).hex(),'type':'ELF'})
    p=_out(outdir,'multi_xor_candidates.json'); p.write_text(json.dumps(hits,indent=2),encoding='utf-8')
    return _result(True,msg=f'{len(hits)} candidates',out=str(p),candidates=hits)

def so_url_dump(path,outdir):
    data=_bytes(path); urls=sorted(set(s for s in _ascii_strings(data,6) if re.match(r'^(?:https?|wss?)://',s,re.I)))
    p=_out(outdir,'urls.txt'); p.write_text('\n'.join(urls)+'\n',encoding='utf-8'); return _result(True,msg=f'{len(urls)} URLs',out=str(p),count=len(urls))

def so_aes_probe(path,outdir):
    data=_bytes(path); hits=[]
    # Report likely AES tables/strings without claiming a key was recovered.
    for marker in (b'AES',b'Rijndael',b'CBC',b'ECB',b'GCM'):
        n=data.count(marker)
        if n: hits.append({'marker':marker.decode(),'count':n})
    return _result(True,msg='AES probe complete',out=_write_json(outdir,'aes_probe',{'hits':hits,'entropy':_entropy(data)}),hits=hits)

def so_patch_url(path,outdir,cfg_path):
    cfg={}
    for line in _p(cfg_path).read_text(encoding='utf-8').splitlines():
        if '=' in line:
            k,v=line.split('=',1); cfg[k.strip()]=v.strip()
    if 'offset' not in cfg or 'new_url' not in cfg: return _result(False,msg='patch_config.txt needs offset=0x... and new_url=...')
    off=int(cfg['offset'],0); new=cfg['new_url'].encode(); data=bytearray(_bytes(path)); oldlen=int(cfg.get('old_len',len(new)),0)
    if off<0 or off+oldlen>len(data): return _result(False,msg='patch offset outside file')
    if len(new)>oldlen: return _result(False,msg='new_url is longer than old_len')
    data[off:off+oldlen]=new+b'\0'*(oldlen-len(new)); out=_out(outdir,_p(path).stem+'_patched'+_p(path).suffix); out.write_bytes(data)
    return _result(True,msg='URL patch complete',out=str(out),offset=off)

# --- Frida script generation ---------------------------------------------
def _frida_js(pkg, include_url=True):
    url_hooks = """
    const strstr = Module.findExportByName('libc.so', 'strstr');
    if (strstr) Interceptor.attach(strstr, { onEnter(args) {
      try { const a = Memory.readUtf8String(args[0]); if (a && /https?:\/\//i.test(a)) send({type:'URL_FOUND',source:'libc->strstr',data:a}); } catch (_) {}
    }});
    const sprintf = Module.findExportByName('libc.so', 'sprintf');
    if (sprintf) Interceptor.attach(sprintf, { onEnter(args) { this.buf=args[0]; }, onLeave(_) {
      try { const a=Memory.readUtf8String(this.buf); if(a && /https?:\/\//i.test(a)) send({type:'URL_FOUND',source:'libc->sprintf',data:a}); } catch (_) {}
    }});
    """
    return f"""Java.perform(function () {{
  console.log('ALVISIA native/JNI trace target: {pkg}');
{url_hooks if include_url else ''}
  try {{
    const env = Java.vm.getEnv();
    const NewStringUTF = env.handle.readPointer().add(Process.pointerSize * 167).readPointer();
    Interceptor.attach(NewStringUTF, {{ onEnter(args) {{
      try {{ const s=Memory.readUtf8String(args[1]); if(s && /https?:\/\//i.test(s)) send({{type:'URL_FOUND',source:'JNI->NewStringUTF',data:s}}); }} catch (_) {{}}
    }} }});
  }} catch (_) {{}}
}});
"""

def frida_generate_script(pkg,outdir):
    p=_out(outdir,'trace.js'); p.write_text(_frida_js(pkg,True),encoding='utf-8'); return _result(True,msg='Frida native/JNI trace script generated',out=str(p),package=pkg)

def frida_jni_hook(pkg,outdir):
    p=_out(outdir,'jni_hook.js'); p.write_text(_frida_js(pkg,False),encoding='utf-8'); return _result(True,msg='Frida JNI hook script generated',out=str(p),package=pkg)

def frida_spawn_trace(pkg,outdir):
    p=_out(outdir,'spawn_trace.sh'); p.write_text(f"#!/system/bin/sh\n# Authorized test-device command.\nfrida -U -f {pkg!r} -l trace.js --no-pause\n",encoding='utf-8'); p.chmod(0o700); return _result(True,msg='Frida spawn command generated',out=str(p),package=pkg)

# --- XOR ------------------------------------------------------------------
def xor_single_byte_scan(path,outdir):
    data=_bytes(path); rows=[]
    for k in range(1,256):
        x=bytes(b^k for b in data[:min(len(data),4096)])
        score=sum(32<=b<127 or b in (9,10,13) for b in x)/max(1,len(x))
        rows.append((score,k))
    rows.sort(reverse=True); p=_out(outdir,'xor_scan.json'); p.write_text(json.dumps([{'key':k,'printable_score':round(s,4)} for s,k in rows[:32]],indent=2),encoding='utf-8')
    return _result(True,msg='XOR scan complete',out=str(p),best_key=rows[0][1])

def xor_apply_key(path,outdir,key):
    key=bytes(key); data=_bytes(path)
    if not key: return _result(False,msg='empty XOR key')
    out=_out(outdir,_p(path).stem+'_xor'+_p(path).suffix); out.write_bytes(bytes(b^key[i%len(key)] for i,b in enumerate(data))); return _result(True,msg='XOR transform complete',out=str(out))

def xor_luas_strip(path,outdir):
    data=_bytes(path)
    for k in range(1,256):
        x=bytes(b^k for b in data[:8])
        if x[:4]==b'\x1bLua' or x[:3]==b'\x1bLJ': return xor_apply_key(path,outdir,bytes([k]))
    ref_words=(0x47362111,0x8DA75746,0xD890849D,0x358C00AB,0xE4F71A26,0xB3B80558,0x2CD00715,0xC8F68F1E)
    ref_key=b''.join(struct.pack('<I',x) for x in ref_words)
    probe=bytes(b^ref_key[i%32] for i,b in enumerate(data[:8]))
    if probe[:4] in (b'\x1bLua',b'LuaS') or probe[:3]==b'\x1bLJ':
        return xor_apply_key(path,outdir,ref_key)
    return _result(False,msg='No supported Lua XOR profile detected')

def xor_batch(batch_dir,outdir,key):
    root=_p(batch_dir); results=[]
    for f in sorted(x for x in root.rglob('*') if x.is_file()):
        results.append(xor_apply_key(f,outdir,key))
    return _result(True,msg=f'processed {len(results)} files',results=results)

# --- PAK deep -------------------------------------------------------------
def _pak_delegate(path,outdir,workdir,mode):
    try:
        import alvsia_core as core
        dest=_p(outdir)/(_p(path).stem+'_'+mode)
        dest.mkdir(parents=True,exist_ok=True)
        if hasattr(core,'run_pak_unpack'):
            r=core.run_pak_unpack(path,dest)
            return _result(bool(r),msg=f'{mode}: delegated PAK unpack',delegate=True,result=r,out=str(dest))
    except Exception as e: return _result(False,msg=f'{mode} unavailable: {e}')
    return _result(False,msg=f'{mode} unavailable in current protected core')

def pak_deep_aes(path,outdir,workdir): return _pak_delegate(path,outdir,workdir,'aes')
def pak_deep_zstd(path,outdir): return _pak_delegate(path,outdir,None,'zstd')
def pak_deep_zuc(path,outdir,workdir): return _pak_delegate(path,outdir,workdir,'zuc')
def pak_deep_sm4(path,outdir,workdir): return _pak_delegate(path,outdir,workdir,'sm4')
def pak_deep_auto(path,outdir,workdir): return _pak_delegate(path,outdir,workdir,'auto')

# --- string recovery ------------------------------------------------------
def string_recover(path,outdir):
    data=_bytes(path); strings=_ascii_strings(data,4); p=_out(outdir,'strings.txt'); p.write_text('\n'.join(strings)+'\n',encoding='utf-8'); return _result(True,msg=f'{len(strings)} strings',out=str(p),count=len(strings))
def string_constant_pool(path,outdir):
    data=_bytes(path); strings=_ascii_strings(data,4); pool=sorted(set(strings)); return _result(True,msg=f'{len(pool)} constants',out=_write_json(outdir,'constant_pool',pool),count=len(pool))
def string_xref(path,outdir):
    data=_bytes(path); strings=_ascii_strings(data,4); rows=[]
    for s in strings[:5000]:
        b=s.encode('ascii','ignore'); pos=[]; start=0
        while b and len(pos)<20:
            i=data.find(b,start)
            if i<0: break
            pos.append(i); start=i+1
        rows.append({'string':s,'offsets':pos})
    return _result(True,msg=f'{len(rows)} strings indexed',out=_write_json(outdir,'xref',rows),count=len(rows))

# --- Lua inject -----------------------------------------------------------
def lua_patch_bytecode(path,outdir,patch_json):
    cfg=json.loads(_p(patch_json).read_text(encoding='utf-8')); off=int(cfg['offset']); val=int(cfg['value'])
    data=bytearray(_bytes(path)); width=int(cfg.get('width',1));
    if off<0 or off+width>len(data): return _result(False,msg='patch offset outside file')
    data[off:off+width]=val.to_bytes(width,'little',signed=False); out=_out(outdir,_p(path).stem+'_patched'+_p(path).suffix); out.write_bytes(data); return _result(True,msg='Lua bytecode patch complete',out=str(out))

def lua_inject_hook(path,outdir,hook_path,jars_dir=None):
    hook=_p(hook_path).read_text(encoding='utf-8'); base=_bytes(path); out=_out(outdir,_p(path).stem+'_hook'+_p(path).suffix); out.write_bytes(base)
    meta=_out(outdir,'hook.lua'); meta.write_text(hook,encoding='utf-8'); return _result(True,msg='Hook material exported; binary injection requires matching Lua VM',out=str(out),hook=str(meta))

def lua_mod_repack(path,outdir,workdir,jars_dir=None):
    src=_p(path); out=_out(outdir,src.stem+'_repack'+src.suffix); shutil.copy2(src,out); return _result(True,msg='Lua repack complete (byte-preserving)',out=str(out))

__all__=[
'audit_apk','audit_lua','audit_so','decrypt_aes','decrypt_auto','decrypt_simple1','decrypt_sm4','decrypt_zuc',
'frida_generate_script','frida_jni_hook','frida_spawn_trace','lua_inject_hook','lua_mod_repack','lua_patch_bytecode',
'pak_deep_aes','pak_deep_auto','pak_deep_sm4','pak_deep_zstd','pak_deep_zuc','so_aes_probe','so_multi_xor','so_patch_url','so_url_dump','so_xor_brute',
'string_constant_pool','string_recover','string_xref','xor_apply_key','xor_batch','xor_luas_strip','xor_single_byte_scan']

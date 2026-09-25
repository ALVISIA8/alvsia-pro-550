from __future__ import annotations
from pathlib import Path
import ast
import re
import shutil
import subprocess
import tempfile
from .detector import detect_lua, LuaInfo

def _find_java():
    for name in ("java", "/system/bin/java", "/data/data/com.alvsia.pro/files/java/bin/java"):
        if shutil.which(name) or Path(name).is_file():
            return name
    return None

def _looks_like_lua_source(text: str) -> bool:
    if not text.strip():
        return False
    # Reject obvious binary garbage while allowing UTF-8 source/comments.
    sample = text[:8192]
    bad = sum(1 for c in sample if ord(c) < 9 or (13 < ord(c) < 32))
    if bad > max(2, len(sample)//100):
        return False
    return bool(re.search(r"\b(?:local|function|return|if|for|while|repeat|do|end)\b", sample))

def validate_lua_source(path_or_text) -> tuple[bool, str]:
    if isinstance(path_or_text, (str, Path)) and Path(str(path_or_text)).is_file():
        text = Path(path_or_text).read_text(encoding="utf-8", errors="replace")
    else:
        text = str(path_or_text)
    if not _looks_like_lua_source(text):
        return False, "output does not look like Lua source"
    # Lightweight structural validation; Lua grammar is not Python grammar.
    pairs = {"end": 0, "function": 0, "if": 0, "for": 0, "while": 0, "do": 0}
    tokens = re.findall(r'(?<![%\w_])(function|if|for|while|repeat|do|end|until)(?![\w_])', text)
    stack = []
    for tok in tokens:
        if tok in ("function", "if", "for", "while", "do", "repeat"):
            stack.append(tok)
        elif tok == "until":
            if not stack or stack[-1] != "repeat":
                return False, "unmatched until"
            stack.pop()
        elif tok == "end":
            if not stack:
                return False, "unmatched end"
            stack.pop()
    if stack:
        return False, "unclosed Lua block(s): " + ",".join(stack[-8:])
    return True, "syntax structure looks consistent"

def _extract_strings(data: bytes, minimum=4):
    out=[]; cur=bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9,):
            cur.append(b)
        else:
            if len(cur)>=minimum:
                out.append(cur.decode("ascii","ignore"))
            cur.clear()
    if len(cur)>=minimum:
        out.append(cur.decode("ascii","ignore"))
    seen=set(); uniq=[]
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq

def _xor_candidate(data: bytes, key: bytes, offset: int):
    if not key or offset >= len(data): return b"", 0.0
    body=bytearray(data[offset:])
    for i in range(len(body)): body[i] ^= key[i % len(key)]
    printable=sum(1 for b in body if b in (9,10,13) or 32 <= b < 127)
    magic=1.0 if body.startswith((b"\x1bLua", b"\x1bLJ")) else 0.0
    ratio=printable/max(1,len(body))
    score=ratio*0.35 + magic*0.65
    return bytes(body), score

def analyze_lua(path, out_dir=None, keys=None):
    p=Path(path); data=p.read_bytes(); info=detect_lua(p)
    result={"ok": True, "file": str(p), "format": info.format,
            "version": info.version, "size": info.size,
            "confidence": info.confidence, "notes": list(info.notes),
            "obfuscation": []}
    if info.kind == "unknown":
        result["ok"]=False
        result["error"]="not recognized as Lua source or bytecode"
        return result
    if info.kind == "source":
        text=data.decode("utf-8","replace")
        patterns={
            "loadstring": r"\bloadstring\s*\(",
            "load": r"\bload\s*\(",
            "debug-library": r"\bdebug\.",
            "getfenv/setfenv": r"\b(?:getfenv|setfenv)\s*\(",
            "goto": r"\bgoto\b",
            "long-escaped-string": r"(?:\\x[0-9A-Fa-f]{2}){4,}",
            "dynamic-code": r"\b(?:assert|pcall|xpcall)\s*\(\s*(?:load|string\.dump)",
        }
        for name,pat in patterns.items():
            if re.search(pat,text): result["obfuscation"].append(name)
        result["source_lines"]=text.count("\n")+1
        return result
    result["strings_count"]=len(_extract_strings(data))
    if info.format=="luajit":
        result["obfuscation"].append("LuaJIT-bytecode")
    if keys:
        candidates=[]
        for key in keys:
            if isinstance(key,str):
                try:key=bytes.fromhex(key)
                except ValueError:continue
            body,score=_xor_candidate(data,key,0)
            candidates.append({"key":key.hex(),"score":round(score,4),
                               "lua_magic":body.startswith((b"\x1bLua",b"\x1bLJ"))})
        result["xor_candidates"]=sorted(candidates,key=lambda x:-x["score"])[:8]
    return result

def decompile_lua(path, out_dir, jars_dir=None, timeout=120):
    p=Path(path); out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    info=detect_lua(p)
    if info.kind=="source":
        dest=out/(p.stem+"_decompiled.lua")
        shutil.copy2(p,dest)
        ok,msg=validate_lua_source(dest)
        return {"ok":ok,"mode":"source-pass-through","out":str(dest),
                "format":info.format,"validation":msg}
    if info.kind!="bytecode":
        return {"ok":False,"error":"input is not recognized Lua bytecode/source",
                "format":info.format}
    if info.format=="luajit":
        return {"ok":False,"error":"LuaJIT bytecode requires a LuaJIT-capable decompiler; no false-success fallback is reported",
                "format":info.format}
    jars=Path(jars_dir) if jars_dir else None
    jar=None
    if jars and jars.is_dir():
        for name in ("unluac_pro.jar","unluac_patched.jar","unluac.jar"):
            q=jars/name
            if q.is_file() and q.stat().st_size>1000:
                jar=q; break
    if jar is None:
        return {"ok":False,"error":"unluac jar not found","format":info.format}
    java=_find_java()
    if not java:
        return {"ok":False,"error":"Java runtime unavailable in this Python environment; Android uses UnluacRunner","format":info.format}
    dest=out/(p.stem+"_decompiled.lua")
    with tempfile.TemporaryDirectory(prefix="alv_lua_") as td:
        safe_in=Path(td)/"input.luac"; safe_jar=Path(td)/"unluac.jar"
        shutil.copy2(p,safe_in); shutil.copy2(jar,safe_jar)
        proc=subprocess.run([java,"-jar",str(safe_jar),str(safe_in)],
                            capture_output=True,text=True,errors="replace",timeout=timeout)
    text=proc.stdout or ""
    stderr=(proc.stderr or "").strip()
    if proc.returncode != 0 or not text.strip():
        return {"ok":False,"error":stderr[:1000] or "decompiler returned no source",
                "returncode":proc.returncode,"format":info.format}
    dest.write_text(text,encoding="utf-8")
    valid,msg=validate_lua_source(dest)
    if not valid:
        dest.unlink(missing_ok=True)
        return {"ok":False,"error":"decompiler output failed Lua structural validation: "+msg,
                "returncode":proc.returncode,"format":info.format}
    return {"ok":True,"out":str(dest),"returncode":proc.returncode,
            "format":info.format,"validation":msg}

def _safe_fold_numeric(text):
    # Only fold simple numeric-only expressions; never eval arbitrary Lua.
    pat=re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s*([+\-*\/])\s*(\d+(?:\.\d+)?)(?![\w.])")
    def repl(m):
        a=float(m.group(1)); b=float(m.group(3)); op=m.group(2)
        try:
            v={"+":a+b,"-":a-b,"*":a*b,"/":a/b}[op]
        except (ZeroDivisionError,KeyError):
            return m.group(0)
        return str(int(v)) if v.is_integer() else repr(v)
    return pat.sub(repl,text)

def clean_lua_source(path, out_path):
    src=Path(path).read_text(encoding="utf-8",errors="replace")
    # Conservative transformations: comments/whitespace are preserved enough
    # for readability; no unsafe control-flow rewriting.
    cleaned=_safe_fold_numeric(src)
    cleaned=re.sub(r"[ \t]+\n","\n",cleaned)
    Path(out_path).parent.mkdir(parents=True,exist_ok=True)
    Path(out_path).write_text(cleaned,encoding="utf-8")
    ok,msg=validate_lua_source(out_path)
    return {"ok":ok,"out":str(out_path),"validation":msg}

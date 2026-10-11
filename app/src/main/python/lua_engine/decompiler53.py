"""
Pure-Python Lua 5.3 bytecode decompiler — two-pass mmap version.
Pass 1: scan the file recording proto positions + debug info (low RAM).
Pass 2: emit Lua source using the pre-scanned data (streaming writes).

Handles files of any size; only debug sections and constant tables are
held in RAM (typically small).
"""
from __future__ import annotations
import mmap, struct, re, math, io
from pathlib import Path
from typing import List, Optional, Any, Dict, Tuple

# ── Opcode table ──────────────────────────────────────────────────────────────
OP = [
    "MOVE","LOADK","LOADKX","LOADBOOL","LOADNIL","GETUPVAL","GETTABUP",
    "GETTABLE","SETTABUP","SETUPVAL","SETTABLE","NEWTABLE","SELF",
    "ADD","SUB","MUL","MOD","POW","DIV","IDIV","BAND","BOR","BXOR",
    "SHL","SHR","UNM","BNOT","NOT","LEN","CONCAT","JMP","EQ","LT","LE",
    "TEST","TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP",
    "TFORCALL","TFORLOOP","SETLIST","CLOSURE","VARARG","EXTRAARG",
]
SIZE_OP=6; SIZE_A=8; SIZE_B=9; SIZE_C=9
POS_OP=0; POS_A=6; POS_B=23; POS_C=14
MAXARG_Bx=(1<<18)-1; MAXARG_sBx=MAXARG_Bx>>1; BITRK=1<<8

def _f(i,pos,sz): return (i>>pos)&((1<<sz)-1)
def decode(ins):
    op=_f(ins,0,6); a=_f(ins,6,8); c=_f(ins,14,9); b=_f(ins,23,9)
    bx=c|(b<<9); sbx=bx-MAXARG_sBx
    return op,a,b,c,bx,sbx
def is_rk(x): return bool(x&BITRK)
def rk_idx(x): return x&~BITRK

MAX_DEPTH=50; LIT_MAX=5_000_000; MAX_EMIT_LINES=100_000

LUA_KW = frozenset([
    "and","break","do","else","elseif","end","false","for","function",
    "goto","if","in","local","nil","not","or","repeat","return",
    "then","true","until","while",
])

def _safe(nm, fb):
    if nm and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', nm): return nm
    return fb

def _lit(v):
    if v is None: return "nil"
    if isinstance(v,bool): return "true" if v else "false"
    if isinstance(v,int): return str(v)
    if isinstance(v,float):
        if math.isnan(v): return "(0/0)"
        if math.isinf(v): return "math.huge" if v>0 else "-math.huge"
        s=repr(v)
        if "." not in s and "e" not in s: s+=".0"
        return s
    if isinstance(v,str):
        e=v.replace("\\","\\\\").replace("\n","\\n").replace("\r","\\r")\
           .replace("\t","\\t").replace('"','\\"')
        return f'"{e}"'
    return repr(v)

def _db(base,key):
    if key.startswith('"') and key.endswith('"'):
        ks=key[1:-1]
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$',ks) and ks not in LUA_KW:
            return f"{base}.{ks}"
    return f"{base}[{key}]"

_BINOP={"ADD":"+","SUB":"-","MUL":"*","MOD":"%","POW":"^","DIV":"/","IDIV":"//",
        "BAND":"&","BOR":"|","BXOR":"~","SHL":"<<","SHR":">>","EQ":"==","LT":"<","LE":"<="}
_UNOP={"UNM":"-","BNOT":"~","NOT":"not ","LEN":"#"}


# ── Low-level mmap reader ─────────────────────────────────────────────────────

class _R:
    """Thin wrapper; all reads go through seek+read on the mmap."""
    __slots__=("mm","pos","sz","int_s","sizet_s","instr_s","lint_s","lnum_s","little")
    def __init__(self, mm):
        self.mm=mm; self.pos=0; self.sz=mm.size()
        self.int_s=4; self.sizet_s=4; self.instr_s=4
        self.lint_s=8; self.lnum_s=8; self.little=True
    def _r(self,n):
        if self.pos+n>self.sz: raise EOFError(f"need {n} at {self.pos}")
        self.mm.seek(self.pos); v=self.mm.read(n); self.pos+=n; return v
    def u8(self): return self._r(1)[0]
    def int_(self):
        return struct.unpack(("<" if self.little else ">")+("i" if self.int_s==4 else "q"),self._r(self.int_s))[0]
    def sizet_(self):
        return struct.unpack(("<" if self.little else ">")+("I" if self.sizet_s==4 else "Q"),self._r(self.sizet_s))[0]
    def lint(self):
        return struct.unpack(("<" if self.little else ">")+("q" if self.lint_s==8 else "i"),self._r(self.lint_s))[0]
    def lnum(self):
        return struct.unpack("<d" if self.little else ">d",self._r(self.lnum_s))[0]
    def string(self):
        sz=self.u8()
        if sz==0xFF: sz=self.sizet_()
        if sz==0: return None
        return self._r(sz-1).decode("utf-8","replace")
    def ins(self):
        return struct.unpack("<I" if self.little else ">I",self._r(self.instr_s))[0]
    def skip(self,n): self.pos=min(self.pos+n,self.sz)


# ── Proto info (pass 1) ───────────────────────────────────────────────────────

class _PInfo:
    """Everything collected in pass 1 for one proto."""
    __slots__=("source","numparams","is_vararg","code_pos","code_n",
               "constants","upvalues","children","locvars","uv_names","parse_err")
    def __init__(self):
        self.source=None; self.numparams=0; self.is_vararg=0
        self.code_pos=0; self.code_n=0
        self.constants=[]; self.upvalues=[]; self.children=[]
        self.locvars=[]; self.uv_names=[]; self.parse_err=None


def _scan(r: _R) -> _PInfo:
    """Pass-1 scan of one proto tree. Fills _PInfo recursively."""
    p=_PInfo()
    try:
        p.source=r.string()
        r.int_(); r.int_()            # linedefined, lastlinedefined
        p.numparams=r.u8(); p.is_vararg=r.u8(); r.u8()  # maxstack
    except EOFError as e:
        p.parse_err=f"hdr:{e}"; return p

    # code — just record position, skip
    try:
        n=r.int_()
        if not(0<=n<=LIT_MAX): raise ValueError(f"code {n}")
        p.code_pos=r.pos; p.code_n=n
        r.skip(n*4)
    except (EOFError,ValueError) as e:
        p.parse_err=f"code:{e}"; return p

    # constants — must read (needed for emit)
    try:
        n=r.int_()
        if not(0<=n<=LIT_MAX): raise ValueError(f"const {n}")
        p.constants=[]
        for _ in range(n):
            t=r.u8()
            if t==0: p.constants.append(None)
            elif t==1: p.constants.append(bool(r.u8()))
            elif t==3: p.constants.append(r.lnum())
            elif t==19: p.constants.append(r.lint())
            elif t in(4,20): p.constants.append(r.string())
            else: p.constants.append(None)
    except (EOFError,ValueError) as e:
        p.parse_err=f"const:{e}"; return p

    # upvalues
    try:
        n=r.int_()
        if not(0<=n<=500_000): raise ValueError(f"uv {n}")
        p.upvalues=[{"instack":r.u8(),"idx":r.u8(),"name":None} for _ in range(n)]
    except (EOFError,ValueError) as e:
        p.parse_err=f"uv:{e}"; return p

    # children (recurse)
    try:
        n=r.int_()
        if not(0<=n<=500_000): raise ValueError(f"ch {n}")
        p.children=[_scan(r) for _ in range(n)]
    except (EOFError,ValueError) as e:
        p.parse_err=f"children:{e}"; return p

    # debug: lineinfo (skip)
    try:
        n=r.int_()
        if not(0<=n<=LIT_MAX): raise ValueError
        r.skip(n*r.int_s)
    except Exception: pass

    # debug: locvars
    try:
        n=r.int_()
        if 0<=n<=500_000:
            for _ in range(n):
                nm=r.string(); s=r.int_(); e=r.int_()
                p.locvars.append({"name":nm,"startpc":s,"endpc":e})
    except Exception: pass

    # debug: upvalue names
    try:
        n=r.int_()
        if 0<=n<=500_000:
            for i in range(n):
                nm=r.string()
                p.uv_names.append(nm)
                if i<len(p.upvalues): p.upvalues[i]["name"]=nm
    except Exception: pass

    return p


# ── Pass-2 emit ───────────────────────────────────────────────────────────────

class _Emitter:
    def __init__(self, mm: mmap.mmap, out, int_s=4, little=True):
        self.mm=mm; self.out=out; self.int_s=int_s; self.little=little
        self.lines=0

    def _w(self, s):
        self.out.write(s); self.out.write("\n"); self.lines+=1

    def emit(self, p: _PInfo, depth: int, par_uvnames: List[str]=None):
        ind="  "*depth
        if p.parse_err:
            self._w(f"{ind}-- [error: {p.parse_err}]"); return

        # upvalue names
        uv: List[str]=[]
        for i,u in enumerate(p.upvalues):
            nm=u.get("name") or (par_uvnames[i] if par_uvnames and i<len(par_uvnames) else None)
            uv.append(_safe(nm,f"_upv{i}"))

        # local name map
        all_lv: List[Tuple[int,int,int,str]]=[]
        for i in range(p.numparams):
            nm=p.locvars[i].get("name") if i<len(p.locvars) else None
            all_lv.append((0,p.code_n,i,_safe(nm,f"a{i}")))
        for i,lv in enumerate(p.locvars):
            nm=_safe(lv.get("name"),f"_v{i}")
            s,e=lv["startpc"],lv["endpc"]
            found=False
            for j,(ss,ee,rr,nn) in enumerate(all_lv):
                if rr==i and ss==0: all_lv[j]=(s,e,i,nm); found=True; break
            if not found: all_lv.append((s,e,i,nm))

        def local_at(pc,reg):
            for sp,ep,r2,nm in all_lv:
                if r2==reg and sp<=pc<ep: return nm
            return None

        def getk(idx):
            if idx>=len(p.constants): return f"_k{idx}"
            return _lit(p.constants[idx])

        # child closures: pre-emit to string buffers (depth+1)
        # children are usually small; main proto is the giant one
        child_strs: List[str]=[]
        for ch in p.children:
            buf=io.StringIO()
            ce=_Emitter(self.mm,buf,self.int_s,self.little)
            ce.emit(ch,depth+1,uv)
            child_strs.append(buf.getvalue()); buf.close()

        regs: Dict[int,str]={}
        ldecl: Dict[int,list]={}
        for sp,ep,r2,nm in all_lv:
            ldecl.setdefault(sp,[]).append((r2,nm))

        def gr(r2,pc):
            nm=local_at(pc,r2)
            if nm: return nm
            return regs.get(r2,f"_r{r2}")
        def grk(x,pc):
            if is_rk(x): return getk(rk_idx(x))
            return gr(x,pc)

        def assign(a,expr,lv_decls):
            nm2=local_at(i+1,a) or f"_r{a}"
            regs[a]=expr
            for r2,nn in lv_decls:
                if r2==a:
                    self._w(f"{ind}local {nn} = {expr}"); regs[a]=nn; return
            self._w(f"{ind}{nm2} = {expr}")

        # Read instructions in chunks to keep RAM low
        CHUNK = 8192
        n = p.code_n
        # We need random access for LOADKX lookahead and skip_pcs,
        # so preload up to MAX_EMIT_LINES worth; if larger, cap and note.
        load_n = min(n, MAX_EMIT_LINES)
        self.mm.seek(p.code_pos)
        raw = self.mm.read(load_n * 4)
        fmt = f"<{load_n}I" if self.little else f">{load_n}I"
        try:
            code = struct.unpack(fmt, raw)
        except struct.error:
            self._w(f"{ind}-- [code unpack error]"); return
        del raw

        skip: set=set()
        i=0; n_emit=len(code); n_total=n
        emitted_here=0
        truncated=(n_total>load_n)
        while i<n_emit:
            if i in skip: i+=1; continue
            ins=code[i]
            op,a,b,c,bx,sbx=decode(ins)
            opname=OP[op] if op<len(OP) else f"OP_{op}"
            lv=ldecl.get(i,[])

            if opname=="MOVE": assign(a,gr(b,i),lv)
            elif opname=="LOADK": assign(a,getk(bx),lv)
            elif opname=="LOADKX":
                val="nil"
                if i+1<n:
                    nxi=code[i+1]; nax=(nxi>>(POS_A+SIZE_A))&((1<<(SIZE_B+SIZE_C))-1)
                    val=getk(nax); skip.add(i+1)
                assign(a,val,lv)
            elif opname=="LOADBOOL":
                assign(a,"true" if b else "false",lv)
                if c: skip.add(i+1)
            elif opname=="LOADNIL":
                for r2 in range(a,a+b+1):
                    nm2=local_at(i+1,r2) or f"_r{r2}"; regs[r2]="nil"
                    self._w(f"{ind}{nm2} = nil")
            elif opname=="GETUPVAL":
                assign(a,uv[b] if b<len(uv) else f"_upv{b}",lv)
            elif opname=="SETUPVAL":
                self._w(f"{ind}{uv[b] if b<len(uv) else f'_upv{b}'} = {gr(a,i)}")
            elif opname=="GETTABUP":
                assign(a,_db(uv[b] if b<len(uv) else f"_upv{b}",grk(c,i)),lv)
            elif opname=="SETTABUP":
                uva=uv[a] if a<len(uv) else f"_upv{a}"
                self._w(f"{ind}{_db(uva,grk(b,i))} = {grk(c,i)}")
            elif opname=="GETTABLE":
                assign(a,_db(gr(b,i),grk(c,i)),lv)
            elif opname=="SETTABLE":
                self._w(f"{ind}{_db(gr(a,i),grk(b,i))} = {grk(c,i)}")
            elif opname=="NEWTABLE": assign(a,"{}",lv)
            elif opname=="SELF":
                expr=_db(gr(b,i),grk(c,i))
                na=local_at(i+1,a) or f"_r{a}"; na1=local_at(i+1,a+1) or f"_r{a+1}"
                regs[a]=expr; regs[a+1]=gr(b,i)
                self._w(f"{ind}{na} = {expr}"); self._w(f"{ind}{na1} = {gr(b,i)}")
            elif opname in _BINOP:
                assign(a,f"{grk(b,i)} {_BINOP[opname]} {grk(c,i)}",lv)
            elif opname in _UNOP:
                assign(a,f"{_UNOP[opname]}{gr(b,i)}",lv)
            elif opname=="CONCAT":
                assign(a," .. ".join(gr(j,i) for j in range(b,c+1)),lv)
            elif opname=="LEN": assign(a,f"#{gr(b,i)}",lv)
            elif opname=="JMP":
                self._w(f"{ind}-- JMP -> {i+sbx+1}")
            elif opname in("EQ","LT","LE"):
                sym={"EQ":"==","LT":"<","LE":"<="}[opname]
                sense="" if a==0 else "not "
                self._w(f"{ind}-- if {sense}({grk(b,i)} {sym} {grk(c,i)}) then")
            elif opname=="TEST":
                self._w(f"{ind}-- if bool({gr(a,i)}) == {bool(c)} then")
            elif opname=="TESTSET":
                self._w(f"{ind}-- if bool({gr(b,i)}) == {bool(c)} then {gr(a,i)} = {gr(b,i)}")
            elif opname=="CALL":
                ac=b-1
                args=([gr(j,i) for j in range(a+1,a+2)]+["..."]
                      if ac<0 else [gr(j,i) for j in range(a+1,a+1+ac)])
                ce2=f"{gr(a,i)}({', '.join(args)})"; rc=c-1
                if rc==0: self._w(f"{ind}{ce2}")
                elif rc==1: assign(a,ce2,lv)
                else:
                    rets=[local_at(i+1,j) or f"_r{j}" for j in range(a,a+rc)]
                    for j,nm2 in enumerate(rets): regs[a+j]=nm2
                    lhs=", ".join(rets)
                    if lv: self._w(f"{ind}local {lhs} = {ce2}")
                    else: self._w(f"{ind}{lhs} = {ce2}")
            elif opname=="TAILCALL":
                ac=b-1
                args=([gr(j,i) for j in range(a+1,a+2)]+["..."]
                      if ac<0 else [gr(j,i) for j in range(a+1,a+1+ac)])
                self._w(f"{ind}return {gr(a,i)}({', '.join(args)})")
            elif opname=="RETURN":
                if b==1: self._w(f"{ind}return")
                elif b==2: self._w(f"{ind}return {gr(a,i)}")
                else:
                    cnt=b-1
                    srcs=([gr(j,i) for j in range(a,a+2)]+["..."]
                          if cnt<0 else [gr(j,i) for j in range(a,a+cnt)])
                    self._w(f"{ind}return {', '.join(srcs)}")
            elif opname=="VARARG":
                if b==1:
                    nm2=local_at(i+1,a) or f"_r{a}"; regs[a]="..."; self._w(f"{ind}{nm2} = ...")
                else:
                    cnt=b-1; names=[]
                    for j in range(a,a+cnt):
                        nm2=local_at(i+1,j) or f"_r{j}"; regs[j]="..."; names.append(nm2)
                    self._w(f"{ind}{', '.join(names)} = ...")
            elif opname=="CLOSURE":
                fn_nm=local_at(i+1,a) or f"_func{bx}"
                for r2,nn in lv:
                    if r2==a: fn_nm=nn; break
                regs[a]=fn_nm
                self._w(f"{ind}local function {fn_nm}(...)")
                if bx<len(child_strs):
                    for cl in child_strs[bx].split("\n"):
                        if cl: self.out.write("  "+cl+"\n"); self.lines+=1
                self._w(f"{ind}end")
            elif opname=="SETLIST":
                tbl=gr(a,i); cnt=b if b>0 else 1; base=(c-1)*50
                for j in range(1,cnt+1): self._w(f"{ind}{tbl}[{base+j}] = {gr(a+j,i)}")
            elif opname=="FORPREP":
                vn=local_at(i+1,a+3) or f"_i{a}"
                self._w(f"{ind}for {vn} = {gr(a,i)}, {gr(a+1,i)}, {gr(a+2,i)} do")
            elif opname=="FORLOOP": self._w(f"{ind}end -- forloop")
            elif opname=="TFORCALL":
                rets=[local_at(i+1,a+3+j) or f"_r{a+3+j}" for j in range(c)]
                self._w(f"{ind}{', '.join(rets)} = {gr(a,i)}({gr(a+1,i)}, {gr(a+2,i)})")
            elif opname=="TFORLOOP": self._w(f"{ind}-- tforloop")
            elif opname=="EXTRAARG": pass
            else: self._w(f"{ind}-- {opname} a={a} b={b} c={c}")
            i+=1; emitted_here+=1
        if truncated:
            self._w(f"{ind}-- [truncated: {n_total-load_n} more instructions omitted]")
        del code


# ── File header ───────────────────────────────────────────────────────────────

def _hdr(r: _R):
    sig=r._r(4)
    if sig!=b"\x1bLua": raise ValueError("not Lua")
    ver=r.u8()
    if ver!=0x53: raise ValueError(f"Lua {ver:#x} not 5.3")
    r.u8(); r._r(6)
    r.int_s=r.u8(); r.sizet_s=r.u8(); r.instr_s=r.u8()
    r.lint_s=r.u8(); r.lnum_s=r.u8()
    r.lint(); r.lnum(); r.u8()


# ── Public API ────────────────────────────────────────────────────────────────

def decompile_file(src: "Path | str", dst: "Path | str") -> dict:
    src=Path(src); dst=Path(dst)
    with open(src,"rb") as fh:
        hdr5=fh.read(5)
    if not hdr5.startswith(b"\x1bLua"):
        return {"ok":False,"error":"not Lua bytecode"}
    if len(hdr5)>4 and hdr5[4]!=0x53:
        return {"ok":False,"error":f"Lua {hdr5[4]:#x} — only 5.3 supported"}

    dst.parent.mkdir(parents=True,exist_ok=True)
    try:
        with open(src,"rb") as fh:
            mm=mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ)
            try:
                r=_R(mm); _hdr(r)
                # Pass 1: scan (low RAM — only constants/locvars held)
                pi=_scan(r)
                # Pass 2: emit
                with open(dst,"w",encoding="utf-8",buffering=131072) as out:
                    out.write("-- Decompiled by ALVSIA PRO  (pure-Python Lua 5.3)\n")
                    out.write(f"-- {src.name}  {src.stat().st_size:,} bytes\n\n")
                    em=_Emitter(mm,out,r.int_s,r.little)
                    em.emit(pi,0,[])
                    lc=em.lines+3
            finally:
                mm.close()
    except Exception as e:
        import traceback
        return {"ok":False,"error":f"decompile failed: {e}",
                "traceback":traceback.format_exc()}

    return {"ok":True,"out":str(dst),"lines":lc,"size":dst.stat().st_size}


def decompile_bytes(data: bytes) -> str:
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".luac",delete=False) as t1:
        s=Path(t1.name); s.write_bytes(data)
    with tempfile.NamedTemporaryFile(suffix=".lua",delete=False) as t2:
        d=Path(t2.name)
    try:
        res=decompile_file(s,d)
        if res.get("ok"): return d.read_text(encoding="utf-8",errors="replace")
        raise ValueError(res.get("error","failed"))
    finally:
        s.unlink(missing_ok=True); d.unlink(missing_ok=True)

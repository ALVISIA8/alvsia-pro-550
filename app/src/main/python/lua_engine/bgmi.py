from __future__ import annotations
from pathlib import Path
import struct

# Independent implementation of the format transform already used by ALVISIA's
# legacy LUA path. It only activates when the caller supplies the XOR key.
BGMI_STD = {0:13,1:14,2:15,3:16,4:17,5:18,14:27,16:29,17:0,18:1,
            20:3,21:4,22:5,23:6,24:7,25:8,26:9,27:10,28:11,29:12,
            30:30,31:31,32:32,33:33,34:34,36:36,37:37,38:38,39:39,
            40:40,41:41,42:42,43:43,44:44,45:45}
STD_BGMI={v:k for k,v in BGMI_STD.items()}
STD_FMT=[0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,2,2,0,2,0,1,0,3]

class _R:
    def __init__(self,d): self.d=d; self.p=0
    def need(self,n):
        if n<0 or self.p+n>len(self.d): raise ValueError("truncated Lua chunk")
    def byte(self): self.need(1); v=self.d[self.p]; self.p+=1; return v
    def u32(self): self.need(4); v=struct.unpack_from("<I",self.d,self.p)[0]; self.p+=4; return v
    def i32(self): self.need(4); v=struct.unpack_from("<i",self.d,self.p)[0]; self.p+=4; return v
    def raw(self,n): self.need(n); v=self.d[self.p:self.p+n]; self.p+=n; return v

class _W:
    def __init__(self): self.b=bytearray()
    def byte(self,v): self.b.append(v&255)
    def u32(self,v): self.b.extend(struct.pack("<I",v&0xffffffff))
    def i32(self,v): self.b.extend(struct.pack("<i",int(v)))
    def raw(self,d): self.b.extend(d)

def transform_bgmi_lua(data: bytes, key: bytes, decrypt=True) -> bytes:
    if len(data)<34 or not data.startswith(b"\x1bLua"):
        raise ValueError("not Lua bytecode")
    if not key: raise ValueError("XOR key is required")
    r,w=_R(data),_W()
    hdr=bytearray(data[:33])
    if decrypt: hdr[13]=8
    elif hdr[12:16]==b"\x04\x08\x04\x08": hdr[12:16]=b"\x04\x04\x04\x08"
    w.raw(hdr); r.p=33; w.byte(r.byte())
    def sread():
        sz=r.byte()
        if sz==255: sz=r.u32()
        if sz==0:return None
        raw=r.raw(sz-1)
        if decrypt:
            raw=bytes(v ^ key[i%len(key)] for i,v in enumerate(raw))
        return raw.decode("utf-8","replace")
    def swrite(s,encrypt):
        if s is None:w.byte(0);return
        raw=s.encode("utf-8") if isinstance(s,str) else bytes(s)
        if encrypt:raw=bytes(v ^ key[i%len(key)] for i,v in enumerate(raw))
        sz=len(raw)+1
        if sz<255:w.byte(sz)
        else:w.byte(255);w.u32(sz)
        w.raw(raw)
    def convert():
        swrite(sread(),not decrypt); w.i32(r.i32()); ldef=r.i32(); w.i32(ldef)
        w.byte(r.byte());w.byte(r.byte());w.byte(r.byte());n=r.u32();w.u32(n)
        for _ in range(n):
            raw=r.u32();op=raw&63;A=(raw>>6)&255;B=(raw>>23)&511;C=(raw>>14)&511
            Bx=(raw>>14)&0x3ffff;Ax=(raw>>6)&0x3ffffff;sBx=Bx-131071
            sop=STD_BGMI.get(op,op) if decrypt else BGMI_STD.get(op,op)
            fmt=STD_FMT[op] if decrypt else (STD_FMT[sop] if sop<len(STD_FMT) else 0)
            if fmt==0:res=(sop&63)|(A<<6)|(C<<14)|(B<<23)
            elif fmt==1:res=(sop&63)|(A<<6)|(Bx<<14)
            elif fmt==2:res=(sop&63)|(A<<6)|((sBx+131071)<<14)
            else:res=(sop&63)|(Ax<<6)
            w.u32(res)
        nk=r.u32();w.u32(nk)
        for _ in range(nk):
            t=r.byte();w.byte(t)
            if t==1:w.byte(r.byte())
            elif t in (3,19):w.raw(r.raw(8))
            elif t in (4,20):swrite(sread(),not decrypt)
        nups=r.u32();w.u32(nups)
        for _ in range(nups):w.byte(r.byte());w.byte(r.byte())
        npt=r.u32();w.u32(npt)
        for _ in range(npt):convert()
        nln=r.u32()
        if decrypt:
            vals=[r.i32() for _ in range(nln)];w.u32(nln);prev=ldef
            for ln in vals:
                diff=ln-prev;prev=ln
                if diff<0:diff+=256
                w.byte(diff&255)
            w.u32(0)
        else:
            cur=ldef; vals=[]
            for _ in range(nln):
                d=r.byte();cur+=d if d<=127 else d-256;vals.append(cur)
            w.u32(len(vals))
            for ln in vals:w.i32(ln)
        if decrypt:
            pass
        else:
            nab=r.u32()
            for _ in range(nab):r.raw(8)
        nloc=r.u32();w.u32(nloc)
        for _ in range(nloc):swrite(sread(),not decrypt);w.i32(r.i32());w.i32(r.i32())
        nupn=r.u32();w.u32(nupn)
        for _ in range(nupn):swrite(sread(),not decrypt)
    convert()
    if r.p>len(data):raise ValueError("parser overrun")
    return bytes(w.b)

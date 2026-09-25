import json, tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app/src/main/python"))
from lua_engine import detect_lua, analyze_lua, validate_lua_source

def main():
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        src=td/"sample.lua"
        src.write_text('local function add(a,b) return a+b end\nreturn add(2,3)\n', encoding="utf-8")
        info=detect_lua(src)
        assert info.kind=="source" and info.format=="lua-source"
        ok,msg=validate_lua_source(src)
        assert ok, msg
        report=analyze_lua(src,td)
        assert report["ok"] and report["format"]=="lua-source"
        luac=td/"sample.luac"; luac.write_bytes(bytes.fromhex("1b4c756153") + b"\\x00"*32)
        li=detect_lua(luac)
        assert li.format=="luac" and li.version=="Lua 5.3"
        lj=td/"sample.lj"; lj.write_bytes(bytes.fromhex("1b4c4a02") + b"\\x00"*20)
        ji=detect_lua(lj)
        assert ji.format=="luajit"
        bad=td/"bad.bin"; bad.write_bytes(b"\\x00\\x01garbage")
        assert not analyze_lua(bad,td)["ok"]
    print("LUA ENGINE TEST: PASS")
if __name__=="__main__": main()

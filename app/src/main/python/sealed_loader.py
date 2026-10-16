# ALVISIA PRO sealed Python bootstrap; payloads are generated during release build.
from __future__ import annotations
import importlib.abc
import importlib.util
import os
import pkgutil
import re
import sys

_BUILD_ID = "ALVISIA-20261010-MAIN-SEAL1"
_MAGIC = b"ALVSEAL2"
_MAP = {
    "alvsia_bridge_impl": "alvsia_bridge_impl.alv",
    "alvsia_core": "alvsia_core.alv",
    "alvsia_ultimate": "alvsia_ultimate.alv",
    "alvsia_features": "alvsia_features.alv",
    "lua_output_validator": "lua_output_validator.alv",
    "lua_string_recover": "lua_string_recover.alv",
    "lua_engine.engine": "lua_engine_engine.alv",
    "lua_engine.decompiler53": "lua_engine_decompiler53.alv",
    "lua_engine.bgmi": "lua_engine_bgmi.alv",
    "lua_engine.luajit_decompiler": "lua_engine_luajit_decompiler.alv",
    "lua_engine.container": "lua_engine_container.alv",
    "lua_engine.detector": "lua_engine_detector.alv",
    "lua_engine.multi_format": "lua_engine_multi_format.alv",
    "lua_engine.vm_deobfuscator": "lua_engine_vm_deobfuscator.alv",
}

def _valid_session() -> bool:
    token = os.environ.get("ALVSIA_SESSION_TOKEN", "")
    return (
        os.environ.get("ALVSIA_APK_SESSION") == "1"
        and re.fullmatch(r"[0-9A-Fa-f]{64}", token) is not None
    )

class _SealedLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, blob: str):
        self.fullname = fullname
        self.blob = blob

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if not _valid_session():
            raise ImportError("sealed runtime authorization missing")
        try:
            # Keep the seed, certificate-derived key, and AES key derivation out
            # of Python. The Kotlin/JNI bridge performs authenticated decryption.
            from com.alvsia.pro.sec import NativeGuard
            raw = pkgutil.get_data("sealed", self.blob)
            if raw is None:
                raise FileNotFoundError("sealed payload resource missing")
            source = bytes(NativeGuard.decryptSealedPayload(raw, _BUILD_ID))
        except Exception as exc:
            raise ImportError("sealed payload authentication/decryption failed") from exc
        module.__file__ = "<ALVISIA-SEALED:%s>" % self.fullname
        module.__package__ = self.fullname.rpartition(".")[0]
        code = compile(source, module.__file__, "exec")
        del source
        exec(code, module.__dict__)

class _SealedFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blob = _MAP.get(fullname)
        if blob is None:
            return None
        return importlib.util.spec_from_loader(fullname, _SealedLoader(fullname, blob))

_installed = False

def install() -> None:
    global _installed
    if _installed:
        return
    if os.environ.get("ALVSIA_SEALED_RUNTIME") != "1":
        raise RuntimeError("sealed runtime is not enabled for this build")
    if not _valid_session():
        raise RuntimeError("sealed runtime requires a valid APK session")
    sys.meta_path.insert(0, _SealedFinder())
    _installed = True

# ALVISIA PRO sealed runtime loader R5.2
# Protected modules are AES-256-GCM sealed and never shipped as plaintext .py.
from __future__ import annotations
import os, sys, hashlib, importlib.abc, importlib.util
from pathlib import Path

_BUILD_ID = 'ALVSIA-20261006-R5.3'
_CERT_SHA256 = '99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c'
_MAP = {'alvsia_core': 'alvsia_core.alv', 'alvsia_ultimate': 'alvsia_ultimate.alv', 'alvsia_features': 'alvsia_features.alv', 'lua_output_validator': 'lua_output_validator.alv', 'lua_string_recover': 'lua_string_recover.alv', 'lua_engine.engine': 'lua_engine_engine.alv', 'lua_engine.decompiler53': 'lua_engine_decompiler53.alv', 'lua_engine.bgmi': 'lua_engine_bgmi.alv', 'lua_engine.luajit_decompiler': 'lua_engine_luajit_decompiler.alv', 'lua_engine.container': 'lua_engine_container.alv', 'lua_engine.detector': 'lua_engine_detector.alv', 'lua_engine.multi_format': 'lua_engine_multi_format.alv', 'lua_engine.vm_deobfuscator': 'lua_engine_vm_deobfuscator.alv'}
_MAGIC = b"ALVSEAL2"

class _Loader(importlib.abc.Loader):
    def __init__(self, fullname, blob): self.fullname, self.blob = fullname, blob
    def create_module(self, spec): return None
    def exec_module(self, module):
        seed_hex = os.environ.get("ALVSIA_SEAL_SEED", "")
        grant = os.environ.get("ALVSIA_OPERATION_GRANT", "")
        measurement_only = os.environ.get("ALVSIA_MEASUREMENT_ONLY", "") == "1"

        # Measurement phase is allowed before the server operation grant.
        # The native build-bound seal seed is still required to decrypt the
        # sealed module. Normal tool execution remains grant-gated.
        if len(seed_hex) != 64:
            raise ImportError("sealed runtime seed unavailable")
        if not grant and not measurement_only:
            raise ImportError("sealed runtime authorization missing")
        try: seed = bytes.fromhex(seed_hex)
        except Exception as e: raise ImportError("sealed runtime key invalid") from e
        key = hashlib.sha256(seed + bytes.fromhex(_CERT_SHA256) + _BUILD_ID.encode()).digest()
        raw = (Path(__file__).resolve().parent / "sealed" / self.blob).read_bytes()
        if not raw.startswith(_MAGIC): raise ImportError("sealed payload header invalid")
        nonce, ct = raw[len(_MAGIC):len(_MAGIC)+12], raw[len(_MAGIC)+12:]
        try:
            if len(ct) < 16:
                raise ValueError("short ciphertext")

            # AES-256-GCM decryption is performed by the native RASP layer.
            # Python receives only the authenticated plaintext bytes.
            from com.alvsia.pro.sec import NativeGuard
            source = bytes(
                NativeGuard.INSTANCE.sealDecrypt(
                    key,
                    nonce,
                    ct[:-16],
                    ct[-16:]
                )
            )
        except Exception as e:
            raise ImportError("sealed payload authentication failed") from e
        module.__file__ = "<ALVSIA-SEALED:%s>" % self.fullname
        module.__package__ = self.fullname.rpartition(".")[0]
        if self.fullname in ("lua_engine",):
            module.__path__ = []
        code = compile(source, module.__file__, "exec")
        del source
        exec(code, module.__dict__)

class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blob = _MAP.get(fullname)
        if blob:
            ispkg = fullname == "lua_engine"
            return importlib.util.spec_from_loader(fullname, _Loader(fullname, blob), is_package=ispkg)
        return None

_installed = False
def install():
    global _installed
    if _installed: return
    if not os.environ.get("ALVSIA_OPERATION_GRANT"):
        raise RuntimeError("sealed runtime requires operation grant")
    if not os.environ.get("ALVSIA_SEAL_SEED"):
        raise RuntimeError("sealed runtime seed unavailable")
    sys.meta_path.insert(0, _Finder())
    _installed = True

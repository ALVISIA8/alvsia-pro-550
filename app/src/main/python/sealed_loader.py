# ALVISIA PRO sealed Python bootstrap; payloads are generated during release build.
from __future__ import annotations
import hashlib
import importlib.abc
import importlib.util
import os
import re
import sys
from pathlib import Path

_BUILD_ID = "ALVISIA-20261010-MAIN-SEAL1"
_CERT_SHA256 = "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
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
        seed_hex = os.environ.get("ALVSIA_SEAL_SEED", "")
        if len(seed_hex) != 64:
            raise ImportError("sealed runtime seed unavailable")
        try:
            seed = bytes.fromhex(seed_hex)
            key = hashlib.sha256(seed + bytes.fromhex(_CERT_SHA256) + _BUILD_ID.encode()).digest()
            raw = (Path(__file__).resolve().parent / "sealed" / self.blob).read_bytes()
            if not raw.startswith(_MAGIC) or len(raw) < len(_MAGIC) + 12 + 16:
                raise ValueError("sealed payload header/length invalid")
            nonce = raw[len(_MAGIC):len(_MAGIC) + 12]
            ciphertext = raw[len(_MAGIC) + 12:]
            # Chaquopy exposes Android's JCA; authenticated decryption fails closed.
            from javax.crypto import Cipher
            from javax.crypto.spec import GCMParameterSpec, SecretKeySpec
            cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(_MAGIC)
            source = bytes(cipher.doFinal(ciphertext))
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
    if len(os.environ.get("ALVSIA_SEAL_SEED", "")) != 64:
        raise RuntimeError("sealed runtime seed unavailable")
    sys.meta_path.insert(0, _SealedFinder())
    _installed = True

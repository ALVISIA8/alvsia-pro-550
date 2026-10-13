#!/usr/bin/env python3
"""Create authenticated ALVSEAL2 payloads and a staged Chaquopy source tree."""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
from pathlib import Path

from Crypto.Cipher import AES

MAGIC = b"ALVSEAL2"
DEFAULT_BUILD_ID = "ALVISIA-20261010-MAIN-SEAL1"
MODULES = {
    "alvsia_bridge_impl": "alvsia_bridge_impl.py",
    "alvsia_core": "alvsia_core.py",
    "alvsia_ultimate": "alvsia_ultimate.py",
    "alvsia_ultimate_compat": "alvsia_ultimate_compat.py",
    "alvsia_features": "alvsia_features.py",
    "lua_output_validator": "lua_output_validator.py",
    "lua_string_recover": "lua_string_recover.py",
    "lua_engine.engine": "lua_engine/engine.py",
    "lua_engine.decompiler53": "lua_engine/decompiler53.py",
    "lua_engine.bgmi": "lua_engine/bgmi.py",
    "lua_engine.luajit_decompiler": "lua_engine/luajit_decompiler.py",
    "lua_engine.container": "lua_engine/container.py",
    "lua_engine.detector": "lua_engine/detector.py",
    "lua_engine.multi_format": "lua_engine/multi_format.py",
    "lua_engine.vm_deobfuscator": "lua_engine/vm_deobfuscator.py",
}


def seal(source: bytes, seed: bytes, cert_digest: bytes, build_id: str) -> bytes:
    key = hashlib.sha256(seed + cert_digest + build_id.encode("utf-8")).digest()
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(MAGIC)
    ciphertext, tag = cipher.encrypt_and_digest(source)
    return MAGIC + nonce + ciphertext + tag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed-hex", default=os.environ.get("ALVSIA_SEAL_SEED_HEX", ""))
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--build-id", default=DEFAULT_BUILD_ID)
    args = parser.parse_args()

    if not args.source.is_dir():
        raise SystemExit("seal: source Python directory does not exist")
    seed_hex = args.seed_hex or ("00" * 32)
    if len(seed_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in seed_hex):
        raise SystemExit("seal: seed must be exactly 64 hexadecimal characters")
    cert_hex = args.cert_sha256.lower()
    if len(cert_hex) != 64 or any(c not in "0123456789abcdef" for c in cert_hex):
        raise SystemExit("seal: certificate SHA-256 must be exactly 64 hexadecimal characters")
    if not args.build_id or len(args.build_id) > 128:
        raise SystemExit("seal: invalid build ID")

    if args.output.exists():
        shutil.rmtree(args.output)
    shutil.copytree(args.source, args.output)
    sealed_dir = args.output / "sealed"
    sealed_dir.mkdir(parents=True, exist_ok=True)
    seed, cert_digest = bytes.fromhex(seed_hex), bytes.fromhex(cert_hex)

    for module, relpath in MODULES.items():
        src = args.source / relpath
        if not src.is_file():
            raise SystemExit("seal: required module missing: " + str(src))
        payload_name = module.replace(".", "_") + ".alv"
        payload = seal(src.read_bytes(), seed, cert_digest, args.build_id)
        (sealed_dir / payload_name).write_bytes(payload)
        staged = args.output / relpath
        if not staged.is_file():
            raise SystemExit("seal: staged module missing: " + str(staged))
        staged.unlink()

    # Remove bytecode caches copied from source; sealed modules must not leave
    # plaintext .pyc files in the Chaquopy archive.
    for cache in args.output.rglob("__pycache__"):
        shutil.rmtree(cache)
    print("sealed %d Python modules into %s" % (len(MODULES), sealed_dir))


if __name__ == "__main__":
    main()

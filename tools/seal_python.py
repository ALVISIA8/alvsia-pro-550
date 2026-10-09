#!/usr/bin/env python3
"""Seal protected ALVISIA Python modules for release packaging; restore source after build."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("Missing dependency: install cryptography before sealing.")

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / "app/src/main/python"
OUT = PY_ROOT / "sealed"
BACKUP = Path(os.environ.get("ALVSIA_PY_BACKUP_DIR", str(Path(tempfile.gettempdir()) / "alvsia-python-source-backup")))
BUILD_ID = "ALVISIA-20261010-MAIN-SEAL1"
CERT_HEX = "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
# Must match NativeGuard.nativeSealSeed(). This is a build-bound obfuscation key,
# not a substitute for server-side authorization or a hardware-backed secret.
SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
MAGIC = b"ALVSEAL2"
MODULES = (
    "alvsia_bridge_impl.py",
    "alvsia_core.py",
    "alvsia_ultimate.py",
    "alvsia_features.py",
    "lua_output_validator.py",
    "lua_string_recover.py",
    "lua_engine/engine.py",
    "lua_engine/decompiler53.py",
    "lua_engine/bgmi.py",
    "lua_engine/luajit_decompiler.py",
    "lua_engine/container.py",
    "lua_engine/detector.py",
    "lua_engine/multi_format.py",
    "lua_engine/vm_deobfuscator.py",
)

def _key() -> bytes:
    return hashlib.sha256(bytes.fromhex(SEED_HEX) + bytes.fromhex(CERT_HEX) + BUILD_ID.encode()).digest()

def restore() -> None:
    manifest = BACKUP / "manifest.json"
    if not manifest.is_file():
        if BACKUP.exists():
            shutil.rmtree(BACKUP, ignore_errors=True)
        print("No protected Python backup to restore.")
        return
    for rel in json.loads(manifest.read_text(encoding="utf-8")):
        saved = BACKUP / rel
        target = PY_ROOT / rel
        if saved.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(saved), str(target))
    if OUT.exists():
        for item in OUT.glob("*.alv"):
            item.unlink()
        try:
            OUT.rmdir()
        except OSError:
            pass
    shutil.rmtree(BACKUP, ignore_errors=True)
    print("Protected Python source restored; generated sealed blobs removed.")

def seal() -> None:
    if BACKUP.exists():
        raise SystemExit(f"Backup already exists at {BACKUP}; restore it before sealing again.")
    sources = [PY_ROOT / rel for rel in MODULES]
    missing = [str(p.relative_to(ROOT)) for p in sources if not p.is_file()]
    if missing:
        raise SystemExit("Missing protected Python source(s): " + ", ".join(missing))
    for cache in PY_ROOT.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    BACKUP.mkdir(parents=True)
    (BACKUP / "manifest.json").write_text(json.dumps(list(MODULES)), encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    for stale_blob in OUT.glob("*.alv"):
        stale_blob.unlink()
    aes = AESGCM(_key())
    try:
        for rel, source in zip(MODULES, sources):
            name = rel.replace("/", "_").removesuffix(".py") + ".alv"
            nonce = os.urandom(12)
            encrypted = aes.encrypt(nonce, source.read_bytes(), MAGIC)
            (OUT / name).write_bytes(MAGIC + nonce + encrypted)
        for rel, source in zip(MODULES, sources):
            saved = BACKUP / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(saved))
        print(f"Sealed {len(MODULES)} protected Python modules; plaintext sources moved outside Chaquopy source tree.")
    except Exception:
        restore()
        raise

def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"--seal", "--restore"}:
        print("usage: seal_python.py --seal|--restore", file=sys.stderr)
        return 2
    if sys.argv[1] == "--seal":
        seal()
    else:
        restore()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

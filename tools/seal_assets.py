#!/usr/bin/env python3
"""Seal APK assets: AES-GCM + random names. No plaintext jar names in APK."""
from __future__ import annotations
import hashlib, os, secrets, struct, sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("pip install cryptography")
    sys.exit(1)

# Must match runtime AssetVault + release cert
CERT_HEX = "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
PKG = "com.alvsia.pro"
MAGIC = b"ALVSA1\x00"

def derive_key() -> bytes:
    raw = (PKG + "|" + CERT_HEX + "|ALV-ASSET-v1").encode()
    return hashlib.sha256(raw).digest()

def seal(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, MAGIC)
    return MAGIC + nonce + ct

def main():
    root = Path(__file__).resolve().parents[1]
    assets = root / "app/src/main/assets"
    src_jars = assets / "unluac"
    out = assets / "nx"
    out.mkdir(parents=True, exist_ok=True)
    key = derive_key()
    mapping = []
    # seal jars under random names
    if src_jars.is_dir():
        for i, jar in enumerate(sorted(src_jars.glob("*.jar"))):
            blob = seal(jar.read_bytes(), key)
            name = secrets.token_hex(8) + ".bin"
            (out / name).write_bytes(blob)
            mapping.append(f"{jar.name}={name}")
            print("sealed", jar.name, "->", name, len(blob))
    # index encrypted too
    idx = "\n".join(mapping).encode()
    (out / "i.dat").write_bytes(seal(idx, key))
    # remove plaintext jars from assets (keep empty marker)
    for jar in src_jars.glob("*.jar"):
        jar.unlink()
        print("removed plaintext", jar.name)
    (src_jars / ".keep").write_text("")
    # neutralize decoy text
    for p in [assets / "fauna/readme.txt", assets / "geo/fetch_hint.cfg"]:
        if p.exists():
            p.write_bytes(secrets.token_bytes(32))
    print("OK sealed -> assets/nx/")

if __name__ == "__main__":
    main()

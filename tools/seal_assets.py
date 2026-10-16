#!/usr/bin/env python3
"""Seal APK assets with AES-GCM and a fresh per-build native seed."""
from __future__ import annotations
import hashlib
import os
import secrets
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("pip install cryptography")
    sys.exit(1)

CERT_HEX = "99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c"
PKG = "com.alvsia.pro"
MAGIC = b"ALVSA1\\x00"
SEED_ENV = "ALVSIA_SEAL_SEED_HEX"


def seed_bytes() -> bytes:
    value = os.environ.get(SEED_ENV, "").strip()
    if len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise SystemExit(f"{SEED_ENV} must be a per-build 64-character hexadecimal value")
    return bytes.fromhex(value)


def derive_key(seed: bytes) -> bytes:
    return hashlib.sha256(seed + bytes.fromhex(CERT_HEX) + b"ALV-ASSET-v2").digest()


def legacy_key() -> bytes:
    # Read-only migration path for the previously committed ALV-ASSET-v1 blobs.
    raw = (PKG + "|" + CERT_HEX + "|ALV-ASSET-v1").encode()
    return hashlib.sha256(raw).digest()


def seal(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
    return MAGIC + nonce + ciphertext


def open_blob(blob: bytes, key: bytes) -> bytes | None:
    if len(blob) < len(MAGIC) + 12 + 16 or not blob.startswith(MAGIC):
        return None
    nonce = blob[len(MAGIC):len(MAGIC) + 12]
    ciphertext = blob[len(MAGIC) + 12:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception:
        return None


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    assets = root / "app/src/main/assets"
    src_jars = assets / "unluac"
    out = assets / "nx"
    out.mkdir(parents=True, exist_ok=True)
    index_path = out / "i.dat"
    seed = seed_bytes()
    key = derive_key(seed)
    entries: list[tuple[str, bytes]] = []

    jars = sorted(src_jars.glob("*.jar")) if src_jars.is_dir() else []
    if jars:
        entries = [(jar.name, jar.read_bytes()) for jar in jars]
    elif index_path.is_file() and index_path.stat().st_size > 0:
        # Re-key the committed legacy payload in memory when source JARs are not
        # present in the CI checkout. Also permits safe repeat runs in one build.
        old_index_blob = index_path.read_bytes()
        index_plain = open_blob(old_index_blob, key)
        old_key = key
        if index_plain is None:
            old_key = legacy_key()
            index_plain = open_blob(old_index_blob, old_key)
        if index_plain is None:
            raise SystemExit("Cannot authenticate existing nx/i.dat; refusing to destroy sealed assets")
        for line in index_plain.decode("utf-8").splitlines():
            if "=" not in line:
                raise SystemExit("Malformed sealed asset index; refusing to continue")
            logical, filename = line.split("=", 1)
            logical, filename = logical.strip(), filename.strip()
            if not logical or not filename or "/" in filename or "\\\\" in filename:
                raise SystemExit("Unsafe entry in sealed asset index")
            blob_path = out / filename
            if not blob_path.is_file():
                raise SystemExit(f"Missing sealed asset payload: {filename}")
            plain = open_blob(blob_path.read_bytes(), old_key)
            if plain is None:
                raise SystemExit(f"Cannot authenticate sealed asset payload: {filename}")
            entries.append((logical, plain))
    else:
        raise SystemExit("No source JARs and no valid existing sealed index")

    if not entries:
        raise SystemExit("No assets to seal")

    # Only replace the existing ciphertext after every previous payload has been
    # authenticated and loaded successfully.
    for stale in out.glob("*.bin"):
        stale.unlink()
    mapping = []
    for logical, plain in entries:
        filename = secrets.token_hex(16) + ".bin"
        (out / filename).write_bytes(seal(plain, key))
        mapping.append(f"{logical}={filename}")
        print("sealed", logical, "->", filename)
    index_path.write_bytes(seal("\\n".join(mapping).encode("utf-8"), key))

    for jar in jars:
        jar.unlink()
        print("removed plaintext", jar)
    if src_jars.is_dir():
        (src_jars / ".keep").write_text("", encoding="utf-8")

    # Replace low-value decoys with non-repeating inert bytes.
    for rel in ("fauna/readme.txt", "geo/fetch_hint.cfg"):
        path = assets / rel
        if path.exists():
            path.write_bytes(secrets.token_bytes(32))
    print(f"OK: {len(entries)} assets sealed using per-build key material")


if __name__ == "__main__":
    main()

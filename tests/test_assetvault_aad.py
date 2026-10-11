#!/usr/bin/env python3
"""Regression guard for the sealed JAR AES-GCM format shared by build and runtime."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "app/src/main/java/com/alvsia/pro/asset/AssetVault.kt"
SEALER = ROOT / "tools/seal_assets.py"

runtime = RUNTIME.read_text(encoding="utf-8")
sealer = SEALER.read_text(encoding="utf-8")

# seal_assets.py authenticates MAGIC as AES-GCM additional authenticated data.
assert "AESGCM(key).encrypt(nonce, data, MAGIC)" in sealer, (
    "asset sealer no longer authenticates MAGIC as AES-GCM AAD"
)
# Android must supply the same AAD before doFinal(), otherwise every sealed blob
# fails authentication and AssetVault silently returns an empty asset map.
aad = runtime.find("c.updateAAD(MAGIC)")
decrypt = runtime.find("c.doFinal(ct)")
assert aad >= 0 and decrypt > aad, (
    "AssetVault must call c.updateAAD(MAGIC) before c.doFinal(ct)"
)
print("PASS: AssetVault AES-GCM AAD matches tools/seal_assets.py")

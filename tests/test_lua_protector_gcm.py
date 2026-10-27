"""Regression tests for the authenticated ALVPROT v2 Lua payload format."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app" / "src" / "main" / "python"))

from Crypto.Cipher import AES
from lua_engine import lua_protector as lp


class TestLuaProtectorAESGCM(unittest.TestCase):
    def setUp(self):
        self.old_session = os.environ.get("ALVSIA_APK_SESSION")
        self.old_token = os.environ.get("ALVSIA_SESSION_TOKEN")
        os.environ["ALVSIA_APK_SESSION"] = "1"
        os.environ["ALVSIA_SESSION_TOKEN"] = "a" * 64
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / "sample.lua"
        self.src.write_bytes(b'local answer = 42\nreturn answer\n')
        self.key = bytes(range(32)).hex()

    def tearDown(self):
        if self.old_session is None:
            os.environ.pop("ALVSIA_APK_SESSION", None)
        else:
            os.environ["ALVSIA_APK_SESSION"] = self.old_session
        if self.old_token is None:
            os.environ.pop("ALVSIA_SESSION_TOKEN", None)
        else:
            os.environ["ALVSIA_SESSION_TOKEN"] = self.old_token
        self.tmp.cleanup()

    def test_encrypt_uses_aes_gcm_and_round_trips(self):
        result = lp.encrypt_lua(self.src, self.root / "encrypted", self.key)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["mode"], "alvprot_v2_aes_gcm")
        blob = Path(result["out"]).read_bytes()
        self.assertEqual(blob[:7], b"ALVPROT")
        self.assertEqual(blob[7], 2)
        self.assertGreaterEqual(len(blob), 44 + 16)

        decrypted = lp.decrypt_lua(result["out"], self.root / "decrypted", self.key)
        self.assertTrue(decrypted.get("ok"), decrypted)
        self.assertEqual(Path(decrypted["out"]).read_bytes(), self.src.read_bytes())

    def test_modified_ciphertext_fails_authentication(self):
        result = lp.encrypt_lua(self.src, self.root / "encrypted", self.key)
        self.assertTrue(result.get("ok"), result)
        path = Path(result["out"])
        blob = bytearray(path.read_bytes())
        blob[44] ^= 0x01
        path.write_bytes(blob)

        decrypted = lp.decrypt_lua(path, self.root / "decrypted", self.key)
        self.assertFalse(decrypted.get("ok"))
        self.assertIn("authentication failed", decrypted.get("error", ""))

    def test_wrong_key_fails_authentication(self):
        result = lp.encrypt_lua(self.src, self.root / "encrypted", self.key)
        self.assertTrue(result.get("ok"), result)
        wrong_key = bytes(reversed(range(32))).hex()
        decrypted = lp.decrypt_lua(result["out"], self.root / "decrypted", wrong_key)
        self.assertFalse(decrypted.get("ok"))
        self.assertIn("authentication failed", decrypted.get("error", ""))

    def test_legacy_v1_payload_remains_readable(self):
        raw_key = bytes(range(32))
        salt = bytes(range(16))
        nonce = bytes(range(12))
        plain = self.src.read_bytes()
        derived = lp._derive_key(raw_key, salt + nonce)
        step1 = lp._xor_stream(plain, derived)
        step2 = lp._block_mix(step1, derived[:16])
        old_ciphertext = lp._xor_stream(step2, derived[16:])
        legacy = lp._pack_header(nonce, salt, len(plain), version=1) + old_ciphertext
        path = self.root / "legacy.alv"
        path.write_bytes(legacy)

        decrypted = lp.decrypt_lua(path, self.root / "legacy-out", raw_key.hex())
        self.assertTrue(decrypted.get("ok"), decrypted)
        self.assertEqual(Path(decrypted["out"]).read_bytes(), plain)


if __name__ == "__main__":
    unittest.main()

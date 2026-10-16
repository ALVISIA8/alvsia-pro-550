import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

# Allow direct execution as `python3 tests/test_seal_python_payloads.py` in CI.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.seal_python_payloads import MAGIC, MODULES, seal


class SealPayloadTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.cert = bytes(range(32, 64))
        self.build_id = "build-1"

    def test_format_and_authenticated_decryption(self):
        plain = b"print('ALVISIA')"
        payload = seal(plain, self.seed, self.cert, self.build_id)
        self.assertTrue(payload.startswith(MAGIC))
        self.assertEqual(len(payload), len(MAGIC) + 12 + len(plain) + 16)
        key = hashlib.sha256(self.seed + self.cert + self.build_id.encode()).digest()
        nonce = payload[len(MAGIC):len(MAGIC) + 12]
        ciphertext = payload[len(MAGIC) + 12:-16]
        tag = payload[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(MAGIC)
        self.assertEqual(cipher.decrypt_and_verify(ciphertext, tag), plain)

    def test_tampering_is_detected(self):
        payload = bytearray(seal(b"source", self.seed, self.cert, self.build_id))
        payload[-1] ^= 1
        key = hashlib.sha256(self.seed + self.cert + self.build_id.encode()).digest()
        nonce = bytes(payload[len(MAGIC):len(MAGIC) + 12])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(MAGIC)
        with self.assertRaises(ValueError):
            cipher.decrypt_and_verify(bytes(payload[len(MAGIC) + 12:-16]), bytes(payload[-16:]))

    def test_random_nonce_changes_payload(self):
        args = (b"source", bytes(32), bytes([1]) * 32, "build-1")
        self.assertNotEqual(seal(*args), seal(*args))

    def test_missing_seed_fails_closed(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "example.py").write_text("VALUE = 1\\n")
            output = root / "generated"
            script = Path(__file__).resolve().parents[1] / "scripts" / "seal_python_payloads.py"
            env = os.environ.copy()
            env.pop("ALVSIA_SEAL_SEED_HEX", None)
            result = subprocess.run([
                sys.executable, str(script), "--source", str(source),
                "--output", str(output), "--cert-sha256", self.cert.hex(),
                "--build-id", self.build_id,
            ], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing an insecure default seed", result.stderr)

    def test_staging_seals_modules_and_removes_plaintext(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            output = root / "generated"
            source.mkdir()
            (source / "alvsia_bridge.py").write_text("def bridge_run_sub(*args): pass")
            (source / "sealed").mkdir()
            (source / "sealed" / "__init__.py").write_text('"""payload resources"""')
            (source / "lua_engine").mkdir()
            (source / "lua_engine" / "__init__.py").write_text('"""lua package"""')
            for relative in MODULES.values():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("VALUE = 'test payload'\n")
            script = Path(__file__).resolve().parents[1] / "scripts" / "seal_python_payloads.py"
            subprocess.run([
                sys.executable, str(script), "--source", str(source),
                "--output", str(output), "--seed-hex", self.seed.hex(),
                "--cert-sha256", self.cert.hex(), "--build-id", self.build_id,
            ], check=True, capture_output=True, text=True)
            payloads = list((output / "sealed").glob("*.alv"))
            self.assertEqual(len(payloads), len(MODULES))
            self.assertTrue((output / "alvsia_bridge.py").is_file())
            for relative in MODULES.values():
                self.assertFalse((output / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()

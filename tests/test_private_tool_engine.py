"""Runtime regression tests for ALVSIA PRIVATE TOOL engine primitives."""
import sys
import unittest
from pathlib import Path

PYTHON_DIR = Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "python"
sys.path.insert(0, str(PYTHON_DIR))

import alvsia_private as private


class PrivateToolEngineTests(unittest.TestCase):
    def test_all_dispatch_dependencies_exist(self):
        for name in (
            "ZUCCipher", "AESKeyScanner", "XORKeyRecovery",
            "LuaBytecodeParser", "LuaOpcodeConverter", "CompressionBestFit",
            "APKAuditor", "StringConstantRecovery", "EntropyAnalyzer",
            "PAKManifestGenerator", "AlvsiaLuaWriter",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(private, name), name)

    def test_zuc128_zero_key_zero_iv_known_answer(self):
        # ZUC-128 standard all-zero test vector begins 27bede74018082da.
        cipher = private.ZUCCipher(bytes(16), bytes(16))
        self.assertEqual(cipher.encrypt(bytes(8)).hex(), "27bede74018082da")

    def test_zuc_rejects_wrong_key_or_iv_length(self):
        with self.assertRaises(ValueError):
            private.ZUCCipher(b"short", bytes(16))
        with self.assertRaises(ValueError):
            private.ZUCCipher(bytes(16), b"short")

    def test_aes_scanner_detects_sbox(self):
        hits = private.AESKeyScanner.scan(private._AES_SBOX)
        self.assertTrue(any(hit["type"] == "sbox_table" for hit in hits))

    def test_entropy_map_handles_empty_and_uniform_data(self):
        self.assertEqual(private.EntropyAnalyzer.block_entropy(b""), 0.0)
        self.assertEqual(private.EntropyAnalyzer.block_entropy(bytes(256)), 0.0)

    def test_compression_best_fit_round_trip(self):
        source = (b"ALVSIA-private-engine-test-" * 100)
        result = private.CompressionBestFit.compress(source, method="zlib")
        self.assertEqual(__import__("zlib").decompress(result), source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

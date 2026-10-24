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


    def test_zuc_encrypt_decrypt_round_trip_with_fresh_instances(self):
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        plaintext = b"ALVSIA ZUC regression payload"
        ciphertext = private.ZUCCipher(key, iv).encrypt(plaintext)
        recovered = private.ZUCCipher(key, iv).decrypt(ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_xor_recovery_returns_empty_for_short_input(self):
        self.assertEqual(private.XORKeyRecovery.recover(b"too short"), [])

    def test_entropy_analyze_reports_offsets_and_bounds(self):
        data = bytes(64) + bytes(range(256))
        blocks = private.EntropyAnalyzer.analyze(data, block_size=64)
        self.assertEqual([offset for offset, _ in blocks], [0, 64, 128, 192, 256])
        self.assertTrue(all(0.0 <= entropy <= 8.0 for _, entropy in blocks))
        self.assertEqual(blocks[0][1], 0.0)

    def test_apk_auditor_reports_zip_structure(self):
        import tempfile
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"binary-manifest-placeholder")
                zf.writestr("classes.dex", b"dex\n035\x00")
                zf.writestr("lib/arm64-v8a/libsample.so", b"\x7fELF")
            report = private.APKAuditor.audit(str(apk))
            self.assertTrue(report["manifest_present"])
            self.assertEqual(report["dex_count"], 1)
            self.assertEqual(report["native_arches"], ["arm64-v8a"])
            self.assertEqual(report["total_files"], 3)

    def test_lua_parser_rejects_non_lua_magic(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            private.LuaBytecodeParser(b"not a lua file").parse()

    def test_compression_target_budget_is_respected(self):
        source = b"A" * 4096
        compressed = private.CompressionBestFit.compress(source, method="zlib", target_size=128)
        self.assertIsNotNone(compressed)
        self.assertLessEqual(len(compressed), 128)
        self.assertEqual(__import__("zlib").decompress(compressed), source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

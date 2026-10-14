import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app" / "src" / "main" / "python"))

from uasset_inspector import UASSET_MAGIC, inspect_asset  # noqa: E402


class UAssetInspectorTests(unittest.TestCase):
    def test_uasset_magic_hash_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.uasset"
            source.write_bytes(struct.pack("<IIII", UASSET_MAGIC, 100, 2, 0))
            (root / "sample.uexp").write_bytes(b"export payload")
            result = inspect_asset(source, root / "out")

            self.assertTrue(result["ok"])
            self.assertTrue(result["unreal_package_magic"])
            self.assertEqual(len(result["sha256"]), 64)
            self.assertTrue(Path(result["report_txt"]).is_file())
            self.assertTrue(Path(result["report_json"]).is_file())
            saved = json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["file"], "sample.uasset")
            self.assertTrue(saved["companions"][0]["exists"])

    def test_unknown_magic_is_warning_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "custom.uasset"
            source.write_bytes(b"CSTM" + b"\x00" * 40)
            result = inspect_asset(source, root / "out")

            self.assertTrue(result["ok"])
            self.assertFalse(result["unreal_package_magic"])
            self.assertTrue(any("custom/encrypted" in note for note in result["notes"]))

    def test_rejects_other_extensions_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            other = root / "file.bin"
            other.write_bytes(b"data")
            self.assertFalse(inspect_asset(other, root / "out")["ok"])
            self.assertFalse(inspect_asset(root / "missing.uexp", root / "out")["ok"])


if __name__ == "__main__":
    unittest.main()

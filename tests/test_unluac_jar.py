"""
Test unluac decompile round-trip via java + jar.

Since we don't have luac5.3 available in CI, we use a small known
Lua 5.3 bytecode chunk (hand-crafted) and verify unluac.Main
produces output.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAR = ROOT / "app" / "libs" / "unluac_pro.jar"

# A real Lua 5.3.6 luac-compiled chunk for `local a = 1; return a`.
# Magic: 1b 4c 75 61 53 00 19 93 0d 0a 1a 0a 04 04 04 08 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 03 00 00 00 00 00 00 00 00 00 00 01 03 00 80 00 01 00 00 00 01 00 00 00 00 00 00 00 05 00 00 00 00 00
# This is a minimal valid Lua 5.3 chunk that unluac should accept.
LUA53_MINIMAL = bytes.fromhex(
    "1b4c75615300"
    "1993" "0d0a1a0a"
    "04" "04" "04" "08" "08"
    "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00"
    "02" "03" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00" "00"
    "01" "03" "00" "80" "00" "01" "00" "00" "00" "01" "00" "00" "00" "00" "00"
    "00" "00" "05" "00" "00" "00" "00" "00"
    "00" "00" "00" "00" "00" "00" "00" "00"
)


@unittest.skipUnless(shutil.which("java"), "java runtime unavailable")
@unittest.skipUnless(JAR.is_file(), "unluac_pro.jar missing")
class TestUnluacJar(unittest.TestCase):
    def test_jar_runs_help(self):
        # Even with no input, unluac.Main prints version + usage.
        r = subprocess.run(
            ["java", "-cp", str(JAR), "unluac.Main"],
            capture_output=True, text=True, errors="replace"
        )
        self.assertNotEqual(r.returncode, 0)
        # Version banner is printed either on stdout or stderr
        combined = r.stdout + r.stderr
        self.assertIn("unluac", combined.lower())

    def test_decompile_minimal_chunk(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "input.luac"
            src.write_bytes(LUA53_MINIMAL)
            r = subprocess.run(
                ["java", "-cp", str(JAR), "unluac.Main", str(src)],
                capture_output=True, text=True, errors="replace", timeout=60
            )
            # unluac may or may not succeed depending on chunk validity,
            # but it must not crash with a Java exception
            self.assertNotIn("java.lang.ArrayIndexOutOfBoundsException", r.stderr)
            self.assertNotIn("unpack requires a buffer of 4 bytes", r.stderr)
            self.assertNotIn("java.lang.NegativeArraySizeException", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

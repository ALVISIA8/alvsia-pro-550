"""
Round-trip test for the ALVSIA VM Protector + Deobfuscator.

Pipeline: original Lua source → vm_protect → protected file →
          pattern detection → vm_deobfuscate → recovered source

Verifies that:
  • vm_protect produces a file that the ALVSEAL3_SOURCE pattern detects
  • vm_deobfuscate reverses the protected file to a byte-identical copy
    of the original source
  • The pattern registry picks the right pattern automatically
  • The protected file IS valid Lua (looks like BGMI pattern: large dispatcher
    + encoded constants + self-executing logic)
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "app" / "src" / "main" / "python"
sys.path.insert(0, str(PY))

from alvsia_vm_protect import (
    vm_protect, vm_extract_payload, vm_decrypt_payload,
    _encrypt, _decrypt, _xor_obfuscate_key, _xor_deobfuscate_key, _runtime_hash16,
)
from lua_engine.pattern_registry import get_registry
from lua_engine.vm_deobfuscator import (
    vm_deobfuscate, detect_alvseal3_source, deobfuscate_alvseal3_source,
    detect_bgmi_vm_pattern, deobfuscate_bgmi_vm_pattern,
)


SAMPLE_LUA = b'''-- Sample Lua module for round-trip test
local M = {}

local function clamp(v, lo, hi)
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

local function compute_score(kills, assists, deaths)
    local base = kills * 100 + assists * 50
    local penalty = deaths * 25
    return clamp(base - penalty, 0, 99999)
end

M.clamp = clamp
M.compute_score = compute_score

print("score:", compute_score(15, 8, 3))
return M
'''


class TestCipher(unittest.TestCase):
    """Low-level cipher + key obfuscation tests."""

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"hello, world! ALVSIA PRO 5.5.0"
        key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
        ciphertext = _encrypt(plaintext, key)
        self.assertNotEqual(plaintext, ciphertext)
        recovered = _decrypt(ciphertext, key)
        self.assertEqual(plaintext, recovered)

    def test_cipher_with_empty_input(self):
        key = b"0123456789abcdef0123456789abcdef"
        self.assertEqual(_encrypt(b"", key), b"")
        self.assertEqual(_decrypt(b"", key), b"")

    def test_cipher_with_large_input(self):
        plaintext = b"X" * 100_000
        key = b"k" * 32
        ciphertext = _encrypt(plaintext, key)
        # XOR cipher must not equal plaintext when state != 0
        self.assertNotEqual(plaintext, ciphertext)
        self.assertEqual(_decrypt(ciphertext, key), plaintext)

    def test_wrong_key_fails_integrity_check(self):
        plaintext = b"sensitive lua source"
        key_correct = b"a" * 32
        key_wrong = b"b" * 32
        ciphertext = _encrypt(plaintext, key_correct)
        # Try decrypt with wrong key — recovered bytes will differ
        wrong_recovered = _decrypt(ciphertext, key_wrong)
        self.assertNotEqual(wrong_recovered, plaintext)

    def test_key_obfuscation_round_trip(self):
        key = bytes(range(32))  # 0,1,2,...,31
        obf = _xor_obfuscate_key(key)
        self.assertNotEqual(key, obf)
        recovered = _xor_deobfuscate_key(obf)
        self.assertEqual(key, recovered)


class TestVMProtectRoundTrip(unittest.TestCase):
    """Full protect → deobfuscate round-trip."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.original = self.tmp / "module.lua"
        self.original.write_bytes(SAMPLE_LUA)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_protect_produces_alvseal3_source(self):
        out = self.tmp / "module.alvlua3.lua"
        result = vm_protect(self.original, out, output_format="lua", num_decoys=64)
        self.assertTrue(result.get("ok"), f"protect failed: {result}")
        self.assertTrue(out.is_file())
        self.assertGreater(out.stat().st_size, len(SAMPLE_LUA))
        # Verify the protected file is recognized as ALVSEAL3_SOURCE
        self.assertTrue(detect_alvseal3_source(out))

    def test_protect_produces_self_executing_lua(self):
        out = self.tmp / "module.alvlua3.lua"
        vm_protect(self.original, out, output_format="lua", num_decoys=16)
        text = out.read_text(encoding="utf-8")
        # Must contain the runtime execution entry point
        self.assertIn("_alvsia_run()", text)
        self.assertIn("_alvsia_decrypt", text)
        self.assertIn("_alvsia_payload", text)
        self.assertIn("_alvsia_key_obf", text)
        self.assertIn("local actual = string.sub(plaintext, 33)", text)
        self.assertIn('local _alvsia_runtime_hash = "%s"' % _runtime_hash16(SAMPLE_LUA), text)
        self.assertIn("load(actual)", text)

    def test_full_round_trip_byte_identical(self):
        protected = self.tmp / "module.alvlua3.lua"
        protect_result = vm_protect(self.original, protected,
                                     output_format="lua", num_decoys=64)
        self.assertTrue(protect_result["ok"])

        out_dir = self.tmp / "out"
        result = vm_deobfuscate(protected, out_dir)
        self.assertTrue(result.get("ok"), f"deobfuscate failed: {result}")
        self.assertTrue(result.get("recovered"))
        self.assertEqual(result.get("mode"), "alvseal3_source")
        self.assertEqual(result.get("pattern_id"), "ALVSEAL3_SOURCE")

        recovered_path = Path(result["out"])
        self.assertTrue(recovered_path.is_file())
        recovered = recovered_path.read_bytes()
        self.assertEqual(recovered, SAMPLE_LUA, "recovered != original")

    def test_deobfuscate_picks_right_pattern(self):
        protected = self.tmp / "module.alvlua3.lua"
        vm_protect(self.original, protected, output_format="lua", num_decoys=8)

        registry = get_registry()
        matches = registry.detect(protected)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].id, "ALVSEAL3_SOURCE")

    def test_deobfuscate_for_unprotected_lua_returns_no_match(self):
        # A plain Lua source file should not match any pattern.
        registry = get_registry()
        matches = registry.detect(self.original)
        self.assertEqual(matches, [])

        result = vm_deobfuscate(self.original, self.tmp / "out2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["mode"], "no_match")


class TestPatternRegistry(unittest.TestCase):
    """Pattern registry contract tests."""

    def test_registry_lists_all_default_patterns(self):
        registry = get_registry()
        ids = {p.id for p in registry.all_patterns()}
        self.assertIn("ALVSEAL3_SOURCE", ids)
        self.assertIn("ALVLUA1_PAYLOAD", ids)
        self.assertIn("BGMI_VM", ids)

    def test_registry_get_by_id(self):
        registry = get_registry()
        p = registry.get("ALVSEAL3_SOURCE")
        self.assertIsNotNone(p)
        self.assertEqual(p.label, "ALVSIA PRO 5.5.0 VM-protected Lua source")

    def test_registry_get_unknown_returns_none(self):
        registry = get_registry()
        self.assertIsNone(registry.get("DOES_NOT_EXIST"))

    def test_registry_can_register_new_pattern(self):
        """Future-proofing: a new pattern can be added at runtime."""
        from lua_engine.pattern_registry import Pattern, register_pattern
        register_pattern(Pattern(
            id="TEST_PATTERN_DUMMY",
            label="Test pattern",
            detector=lambda p: False,
            deobfuscator=lambda p, o: {"ok": False},
        ))
        registry = get_registry()
        p = registry.get("TEST_PATTERN_DUMMY")
        self.assertIsNotNone(p)


class TestBGMI_VMPattern(unittest.TestCase):
    """Tests against the real BGMI-protected file if available."""

    REAL_FILE = ROOT / "work" / "ALVSIA" / "IN" / "LUA" / "BRPlayerCharacterBase.lua"

    def setUp(self):
        if not self.REAL_FILE.is_file():
            self.skipTest(f"Real BGMI file not present: {self.REAL_FILE}")

    def test_detect_bgmi_vm_pattern_on_real_file(self):
        self.assertTrue(detect_bgmi_vm_pattern(self.REAL_FILE),
                        "BGMI-VM detector must match the real file")

    def test_deobfuscate_bgmi_vm_returns_partial_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            result = deobfuscate_bgmi_vm_pattern(self.REAL_FILE, out_dir)
            self.assertTrue(result.get("ok"), "BGMI deobfuscator should return ok=True")
            self.assertFalse(result.get("recovered"),
                            "BGMI deobfuscator must NOT claim full source recovery")
            self.assertEqual(result.get("mode"), "bgmi_vm_partial")
            self.assertIn("structure_out", result)
            self.assertIn("constants_out", result)
            self.assertIn("report_out", result)
            # Verify output files exist
            self.assertTrue(Path(result["structure_out"]).is_file())
            self.assertTrue(Path(result["constants_out"]).is_file())
            self.assertTrue(Path(result["report_out"]).is_file())

    def test_deobfuscate_via_top_level_dispatcher_on_real_file(self):
        """Top-level vm_deobfuscate picks BGMI_VM pattern for the real file."""
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            result = vm_deobfuscate(self.REAL_FILE, out_dir)
            self.assertTrue(result.get("ok"))
            self.assertEqual(result.get("pattern_id"), "BGMI_VM")
            self.assertFalse(result.get("recovered"))  # honest partial


class TestBGMI_VMDetectionRules(unittest.TestCase):
    """Sanity tests for the BGMI-VM detection rules."""

    def test_small_lua_file_is_not_bgmi(self):
        # A small Lua source file must not trigger BGMI-VM
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "small.lua"
            p.write_text("local x = 1\nreturn x\n")
            self.assertFalse(detect_bgmi_vm_pattern(p))

    def test_small_luac_chunk_is_not_bgmi(self):
        # A minimal luac chunk (header + tiny main) must not trigger BGMI-VM
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "small.luac"
            # Standard Lua 5.3 header + minimal main function
            header = bytes.fromhex(
                "1b4c75615300" "1993" "0d0a1a0a"
                "04" "04" "04" "08" "08"
                + "00" * 6  # LUAC_INT (placeholder)
                + "00" * 8  # LUAC_NUM (placeholder)
                + "01"  # upvalue count
                + "00"  # source = None
                + "00 00 00 00"  # linedefined
                + "00 00 00 00"  # lastlinedefined
                + "00"  # numparams
                + "01"  # is_vararg
                + "02"  # maxstacksize
                + "01 00 00 00"  # code count = 1
                + "26 00 00 00"  # RETURN instruction
                + "00 00 00 00"  # constants = 0
                + "01 00 00 00"  # upvalues = 1
                + "00 00"  # instack, idx
                + "00 00 00 00"  # nested protos = 0
            )
            p.write_bytes(header)
            self.assertFalse(detect_bgmi_vm_pattern(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)

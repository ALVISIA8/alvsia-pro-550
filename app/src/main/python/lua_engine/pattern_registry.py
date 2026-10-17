"""
ALVSIA PRO 5.5.0 — Lua Protection Pattern Registry.

Extensible registry of known Lua bytecode / source protection patterns.
Each pattern has:
  • id              : stable short identifier (e.g. "ALVSEAL3", "BGMI_VM")
  • label           : human-readable name
  • detector        : fn(input_path) -> bool    (does this file match?)
  • deobfuscator    : fn(input_path, out_dir) -> dict
                      (extract what's possible; produce original source if known)
  • notes           : explanation of pattern + recovery potential

The streaming_decompiler + bridge consult this registry when standard
decompilers fail. To support a new protection scheme:
  1. Add a Pattern entry here.
  2. Implement detect_<id>() and deobfuscate_<id>() in vm_deobfuscator.py.
  3. The framework picks it up automatically on the next tool run.

This is how ALVISIA PRO stays future-proof: instead of rewriting the
decompiler for every new protection, you add a new pattern entry and
the rest of the pipeline reuses it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any


@dataclass
class Pattern:
    id: str
    label: str
    detector: Callable[[Path], bool]
    deobfuscator: Callable[[Path, Path], Dict[str, Any]]
    notes: str = ""
    confidence_boost: float = 0.0  # how much confidence this adds to detection


# ── Detectors are imported from vm_deobfuscator to avoid circular imports ──
# The actual registration happens in register_default_patterns() below.


def _register_defaults() -> List[Pattern]:
    """Return the default set of patterns. Imported lazily so that
    vm_deobfuscator can implement its detectors without a circular import."""
    from .vm_deobfuscator import (
        detect_alvseal3_source,
        deobfuscate_alvseal3_source,
        detect_alvlua1_payload,
        deobfuscate_alvlua1_payload,
        detect_bgmi_vm_pattern,
        deobfuscate_bgmi_vm_pattern,
    )
    return [
        Pattern(
            id="ALVSEAL3_SOURCE",
            label="ALVSIA PRO 5.5.0 VM-protected Lua source",
            detector=detect_alvseal3_source,
            deobfuscator=deobfuscate_alvseal3_source,
            notes=(
                "Self-executing Lua source file produced by alvsia_vm_protect. "
                "Contains _alvsia_payload + _alvsia_key_obf string literals + a "
                "VM dispatcher dummy function. Fully reversible because the "
                "key is embedded (XOR-obfuscated). Recovery = original source."
            ),
            confidence_boost=0.95,
        ),
        Pattern(
            id="ALVLUA1_PAYLOAD",
            label="ALVSIA PRO AES-256-GCM Lua payload",
            detector=detect_alvlua1_payload,
            deobfuscator=deobfuscate_alvlua1_payload,
            notes=(
                "Raw encrypted payload produced by lua_protect_encrypt (module 18). "
                "Header ALVLUA1 + 12-byte nonce + 16-byte GCM tag + ciphertext. "
                "Requires the 64-hex key from WORK/lua_protect_key.txt to decrypt. "
                "If the key is wrong, recovery fails closed (GCM tag mismatch)."
            ),
            confidence_boost=0.9,
        ),
        Pattern(
            id="BGMI_VM",
            label="BGMI / PUBG Mobile Lua VM obfuscation",
            detector=detect_bgmi_vm_pattern,
            deobfuscator=deobfuscate_bgmi_vm_pattern,
            notes=(
                "Pattern: Lua 5.3 header is standard, but main function has "
                "tens of thousands of instructions (typically >1000) and nested "
                "proto has hundreds to thousands of constants with no code. "
                "This indicates a custom VM interpreter + encoded bytecode. "
                "Full source recovery requires reverse-engineering the VM "
                "opcode table — that is a separate RE project. ALVSIA extracts "
                "structure + constants honestly and reports 'partial recovery'."
            ),
            confidence_boost=0.7,
        ),
    ]


class PatternRegistry:
    """Holds all known protection patterns. Lookup by detection result."""

    def __init__(self):
        self._patterns: List[Pattern] = []
        self._by_id: Dict[str, Pattern] = {}

    def register(self, pattern: Pattern) -> None:
        if pattern.id in self._by_id:
            return  # already registered
        self._patterns.append(pattern)
        self._by_id[pattern.id] = pattern

    def detect(self, input_path: Path) -> List[Pattern]:
        """Return all patterns that match the input file (in registration order)."""
        out = []
        for p in self._patterns:
            try:
                if p.detector(input_path):
                    out.append(p)
            except Exception:
                continue  # a buggy detector never blocks others
        return out

    def best_match(self, input_path: Path) -> Optional[Pattern]:
        """Return the highest-confidence matching pattern, or None."""
        matches = self.detect(input_path)
        if not matches:
            return None
        return max(matches, key=lambda p: p.confidence_boost)

    def get(self, pattern_id: str) -> Optional[Pattern]:
        return self._by_id.get(pattern_id)

    def all_patterns(self) -> List[Pattern]:
        return list(self._patterns)


# ── Module-level singleton ───────────────────────────────────────────────────

_REGISTRY: Optional[PatternRegistry] = None


def get_registry() -> PatternRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PatternRegistry()
        for p in _register_defaults():
            _REGISTRY.register(p)
    return _REGISTRY


def register_pattern(pattern: Pattern) -> None:
    """Add a new pattern at runtime. Use to extend ALVSIA for new protection schemes."""
    get_registry().register(pattern)


def list_patterns() -> List[Dict[str, Any]]:
    """Return pattern metadata for UI display / debugging."""
    return [
        {
            "id": p.id,
            "label": p.label,
            "notes": p.notes,
            "confidence_boost": p.confidence_boost,
        }
        for p in get_registry().all_patterns()
    ]

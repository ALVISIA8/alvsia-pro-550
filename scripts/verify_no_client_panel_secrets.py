#!/usr/bin/env python3
"""Reject obvious server-shared secrets in shipped Android client sources/config."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [ROOT / "app/src/main", ROOT / "app/build.gradle.kts", ROOT / "gradle.properties"]
EXTENSIONS = {".kt", ".java", ".py", ".xml", ".properties", ".kts", ".c", ".cc", ".cpp", ".h", ".hpp"}
PATTERNS = (
    ("server API secret assignment", re.compile(r"""\b(?:API_SECRET|PANEL_API_SECRET|CLIENT_SHARED_SECRET|PANEL_SHARED_SECRET)\b\s*[:=]""", re.I)),
    ("embedded secret in a common config key", re.compile(r"""\b(?:apiSecret|panelApiSecret|clientSharedSecret|panelSharedSecret)\b\s*[:=]""", re.I)),
)

def candidates():
    for root in SCAN_ROOTS:
        if root.is_file():
            yield root
        elif root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in EXTENSIONS:
                    yield path

def main():
    failures = []
    for path in candidates():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            failures.append(f"{path.relative_to(ROOT)}: unreadable ({exc})")
            continue
        for label, pattern in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(ROOT)}:{line}: possible {label}")
    if failures:
        print("CLIENT SECRET GATE FAIL:")
        print("\n".join(f" - {item}" for item in failures))
        return 1
    print("Client secret gate passed: no obvious server-shared-secret assignments in shipped Android sources/config.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

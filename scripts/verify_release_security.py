#!/usr/bin/env python3
"""Compatibility entry point; delegates to the canonical, exact-inventory APK audit."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_release_apk import main

if __name__ == "__main__":
    raise SystemExit(main())

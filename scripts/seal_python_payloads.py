#!/usr/bin/env python3
"""Deprecated legacy sealer; fail closed to prevent building with a stale module inventory."""
raise SystemExit(
    "Deprecated: this duplicate sealer has an incomplete inventory. "
    "Use tools/seal_python.py --seal in the supported release pipeline."
)

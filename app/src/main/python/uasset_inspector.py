"""Read-only Unreal Engine .uasset/.uexp header and sidecar inspection.

This module intentionally does not patch, decrypt, or rewrite game assets.
It provides a defensive first-pass report; package-summary layouts vary by
Unreal Engine version and game build, so raw header words are not over-decoded.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

UASSET_MAGIC = 0x9E2A83C1
MAX_HEADER_BYTES = 256


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _companions(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".uasset":
        candidates = (path.with_suffix(".uexp"), path.with_suffix(".ubulk"),
                      path.with_suffix(".uptnl"))
    elif suffix == ".uexp":
        candidates = (path.with_suffix(".uasset"), path.with_suffix(".ubulk"),
                      path.with_suffix(".uptnl"))
    else:
        candidates = ()
    return [
        {"name": candidate.name, "exists": candidate.is_file(),
         "size_bytes": candidate.stat().st_size if candidate.is_file() else None}
        for candidate in candidates
    ]


def inspect_asset(input_path: str | Path, out_dir: str | Path) -> dict[str, Any]:
    """Inspect a .uasset or .uexp file and write TXT + JSON reports."""
    source = Path(input_path)
    destination = Path(out_dir)
    if not source.is_file():
        return {"ok": False, "error": "Input file does not exist"}
    if source.suffix.lower() not in {".uasset", ".uexp"}:
        return {"ok": False, "error": "Select a .uasset or .uexp file"}

    try:
        with source.open("rb") as stream:
            header = stream.read(MAX_HEADER_BYTES)
        size = source.stat().st_size
        magic = struct.unpack("<I", header[:4])[0] if len(header) >= 4 else None
        is_uasset_magic = magic == UASSET_MAGIC
        words = []
        for offset in range(0, min(len(header), 64) - 3, 4):
            value = struct.unpack_from("<I", header, offset)[0]
            words.append({"offset": offset, "hex": f"0x{value:08X}", "decimal": value})

        companions = _companions(source)
        report: dict[str, Any] = {
            "ok": True,
            "file": source.name,
            "extension": source.suffix.lower(),
            "size_bytes": size,
            "sha256": _sha256(source),
            "header_hex": header[:64].hex(" "),
            "unreal_package_magic": is_uasset_magic if source.suffix.lower() == ".uasset" else None,
            "magic_value": f"0x{magic:08X}" if magic is not None else None,
            "header_words_little_endian": words,
            "companions": companions,
            "notes": [],
        }
        if source.suffix.lower() == ".uasset" and not is_uasset_magic:
            report["notes"].append(
                "Standard Unreal package magic was not found at offset 0; this may be a custom/encrypted format."
            )
        if source.suffix.lower() == ".uexp" and not any(
            item["name"].endswith(".uasset") and item["exists"] for item in companions
        ):
            report["notes"].append("Matching .uasset sidecar was not found beside this .uexp file.")
        report["notes"].append(
            "Header words are raw triage data; exact field meanings depend on Unreal Engine version and game format."
        )

        destination.mkdir(parents=True, exist_ok=True)
        stem = source.stem
        txt_path = destination / f"{stem}_asset_inspection.txt"
        json_path = destination / f"{stem}_asset_inspection.json"
        lines = [
            "ALVISIA PRO — UAsset/UEXP Read-only Inspection",
            f"File: {report['file']}",
            f"Type: {report['extension']}",
            f"Size: {size} bytes",
            f"SHA-256: {report['sha256']}",
            f"Header (first {min(len(header), 64)} bytes): {report['header_hex']}",
            f"Unreal package magic: {'MATCH' if is_uasset_magic else 'NOT CONFIRMED'}"
            if source.suffix.lower() == ".uasset" else "Unreal package magic: not applicable to .uexp",
            "",
            "Header words (little-endian, raw offsets):",
        ]
        lines.extend(
            f"  +0x{word['offset']:02X}: {word['hex']} ({word['decimal']})"
            for word in words
        )
        lines.extend(["", "Sidecar files:"])
        lines.extend(
            f"  {item['name']}: {'present (' + str(item['size_bytes']) + ' bytes)' if item['exists'] else 'not found'}"
            for item in companions
        )
        lines.extend(["", "Notes:"])
        lines.extend(f"  - {note}" for note in report["notes"])
        lines.extend(["", "No source asset was modified."])
        txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report["report_txt"] = str(txt_path)
        report["report_json"] = str(json_path)
        return report
    except (OSError, ValueError, struct.error) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

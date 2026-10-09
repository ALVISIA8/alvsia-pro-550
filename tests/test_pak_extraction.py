"""Regression tests for fail-closed PAK block extraction."""
import sys
import tempfile
import zlib
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app/src/main/python"))
import alvsia_core as core


def test_zlib_and_raw_deflate_blocks():
    plain = (b"Lua protected payload regression\n" * 200)
    wrapped = zlib.compress(plain)
    assert core.PakCompression.decompress_block(wrapped, None, core.CM_ZLIB) == plain

    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = compressor.compress(plain) + compressor.flush()
    assert core.PakCompression.decompress_block(raw, None, core.CM_ZLIB) == plain


def test_corrupt_zlib_is_rejected_not_returned_as_plaintext():
    try:
        core.PakCompression.decompress_block(b"not-a-deflate-stream", None, core.CM_ZLIB)
    except ValueError as exc:
        assert "decompression failed" in str(exc).lower()
    else:
        raise AssertionError("corrupt compressed block was silently accepted")


def test_write_is_atomic_and_checks_decompressed_size():
    plain = b"Lua payload: validated"
    compressed = zlib.compress(plain)
    pak = core.TencentPakFile.__new__(core.TencentPakFile)
    pak._file_content = memoryview(compressed)
    pak._zstd_dict = None
    entry = SimpleNamespace(
        encryption_method=0,
        compression_method=core.CM_ZLIB,
        compressed_blocks=[SimpleNamespace(start=0, end=len(compressed))],
        encrypted=False,
        uncompressed_size=len(plain),
    )
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "sample.lua"
        dest.write_bytes(b"old-output-must-not-survive-as-success")
        pak._write_to_disk(dest, entry)
        assert dest.read_bytes() == plain
        assert not Path(str(dest) + ".alvsia-tmp").exists()

        corrupt_entry = SimpleNamespace(
            encryption_method=0,
            compression_method=core.CM_ZLIB,
            compressed_blocks=[SimpleNamespace(start=0, end=len(b"corrupt"))],
            encrypted=False,
            uncompressed_size=100,
        )
        pak._file_content = memoryview(b"corrupt")
        dest.write_bytes(b"keep-prior-file-if-operation-fails")
        try:
            pak._write_to_disk(dest, corrupt_entry)
        except ValueError:
            pass
        else:
            raise AssertionError("corrupt entry did not fail")
        assert dest.read_bytes() == b"keep-prior-file-if-operation-fails"
        assert not Path(str(dest) + ".alvsia-tmp").exists()


def main():
    tests = (
        test_zlib_and_raw_deflate_blocks,
        test_corrupt_zlib_is_rejected_not_returned_as_plaintext,
        test_write_is_atomic_and_checks_decompressed_size,
    )
    for test in tests:
        test()
        print("PASS", test.__name__)
    print("PAK EXTRACTION REGRESSION: PASS (3/3)")


if __name__ == "__main__":
    main()

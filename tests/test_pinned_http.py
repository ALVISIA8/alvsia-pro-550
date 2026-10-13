import unittest

from app.src.main.python.pinned_http import extract_spki_der, panel_post


def tlv(tag, value):
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


class PinnedHttpTests(unittest.TestCase):
    def test_extracts_spki_der_from_certificate_shape(self):
        version = tlv(0xA0, tlv(0x02, b"\x02"))
        serial = tlv(0x02, b"\x01")
        signature = tlv(0x30, b"")
        issuer = tlv(0x30, b"")
        validity = tlv(0x30, b"")
        subject = tlv(0x30, b"")
        spki = tlv(0x30, tlv(0x02, b"\x01"))
        tbs = tlv(0x30, version + serial + signature + issuer + validity + subject + spki)
        certificate = tlv(0x30, tbs + tlv(0x30, b"") + tlv(0x03, b"\x00"))
        self.assertEqual(extract_spki_der(certificate), spki)

    def test_rejects_unpinned_host_and_cleartext(self):
        for url in ("http://alvsiapro.cc.cd/api", "https://example.com/api"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    panel_post(url, json={})


if __name__ == "__main__":
    unittest.main()

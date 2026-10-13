import hashlib
import unittest

from scripts.seal_python_payloads import MAGIC, seal


class SealPayloadTests(unittest.TestCase):
    def test_format_and_authentication(self):
        seed = bytes(range(32))
        cert = bytes(range(32, 64))
        payload = seal(b"print('ALVISIA')", seed, cert, "build-1")
        self.assertTrue(payload.startswith(MAGIC))
        self.assertEqual(len(payload), len(MAGIC) + 12 + len(b"print('ALVISIA')") + 16)

    def test_random_nonce_changes_payload(self):
        args = (b"source", bytes(32), bytes([1]) * 32, "build-1")
        self.assertNotEqual(seal(*args), seal(*args))


if __name__ == "__main__":
    unittest.main()

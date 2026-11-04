"""WireGuard public keys must have a unique canonical base64 representation."""
import base64
import tempfile
from pathlib import Path
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError, check_key


class CanonicalPublicKeyTests(unittest.TestCase):
    def test_canonical_public_key_is_accepted(self):
        canonical = base64.b64encode(bytes([1]) * 32).decode("ascii")
        self.assertEqual(check_key(canonical), canonical)

    def test_nonzero_base64_pad_bits_are_rejected(self):
        canonical = base64.b64encode(bytes([1]) * 32).decode("ascii")
        # For a 32-byte key, the last base64 character has two unused bits.
        # E (000100) and F (000101) decode to the same final byte.
        alias = canonical[:-2] + "F="
        self.assertNotEqual(alias, canonical)
        self.assertEqual(base64.b64decode(alias, validate=True),
                         base64.b64decode(canonical, validate=True))
        with self.assertRaises(ValidationError):
            check_key(alias)

    def test_alias_cannot_be_enrolled_as_second_identity(self):
        canonical = base64.b64encode(bytes([1]) * 32).decode("ascii")
        alias = canonical[:-2] + "F="
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                store.add_peer("first", canonical, ["users"])
                with self.assertRaises(ValidationError):
                    store.add_peer("alias", alias, ["users"])
                self.assertEqual([p["name"] for p in store.peers()], ["first"])
                self.assertEqual(len(store.events()), 1)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

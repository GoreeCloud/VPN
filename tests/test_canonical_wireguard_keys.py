"""Regression: base64 padding bits cannot create a second identity for one key."""

import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError, check_key


class CanonicalWireGuardKeyTests(unittest.TestCase):
    def test_noncanonical_padding_bits_are_rejected(self):
        raw = bytes(range(1, 33))
        canonical = base64.b64encode(raw).decode("ascii")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = canonical[-2]
        # 32 bytes use two base64 padding bits; toggling one does not
        # change the decoded key, but does change the textual identity.
        alternate = canonical[:-2] + alphabet[alphabet.index(last) ^ 1] + "="
        self.assertNotEqual(canonical, alternate)
        self.assertEqual(base64.b64decode(canonical), base64.b64decode(alternate))
        self.assertEqual(check_key(canonical), canonical)
        with self.assertRaises(ValidationError):
            check_key(alternate)

    def test_revoked_key_cannot_be_reenrolled_with_alternate_encoding(self):
        canonical = base64.b64encode(bytes(range(1, 33))).decode("ascii")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        alternate = canonical[:-2] + alphabet[alphabet.index(canonical[-2]) ^ 1] + "="
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                peer = store.add_peer("first", canonical, ["users"])
                self.assertTrue(store.revoke_peer(peer["id"]))
                with self.assertRaises(ValidationError):
                    store.add_peer("second", alternate, ["users"])
                self.assertEqual(len(store.peers()), 1)
                self.assertEqual(store.peers()[0]["status"], "revoked")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

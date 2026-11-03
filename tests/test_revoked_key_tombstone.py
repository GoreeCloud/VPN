"""Offline regression tests for terminal peer revocation and key tombstones.

These assert management-plane state only, not WireGuard packet enforcement.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class RevokedKeyTombstoneTests(unittest.TestCase):
    def test_revoked_key_cannot_reenroll_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "vpn.db"
            store = VPNStore(database)
            try:
                old = store.add_peer("laptop", public_key(21), ["users"])
                server = store.add_peer("server", public_key(22), ["servers"])
                store.add_policy("users", "servers", "tcp", [22])
                self.assertTrue(store.approve_peer(old["id"]))
                self.assertTrue(store.approve_peer(server["id"]))
                self.assertTrue(store.allowed(old["id"], server["id"], "tcp", 22))

                self.assertTrue(store.revoke_peer(old["id"]))
                self.assertFalse(store.allowed(old["id"], server["id"], "tcp", 22))
                self.assertFalse(store.approve_peer(old["id"]))
                self.assertFalse(store.revoke_peer(old["id"]))
            finally:
                store.close()

            store = VPNStore(database)
            try:
                self.assertFalse(store.allowed(old["id"], server["id"], "tcp", 22))
                self.assertEqual(
                    next(peer["status"] for peer in store.peers() if peer["id"] == old["id"]),
                    "revoked",
                )
                with self.assertRaises(ValidationError):
                    store.add_peer("replacement", public_key(21), ["users"])
                with self.assertRaises(ValidationError):
                    store.add_peer("laptop", public_key(23), ["users"])

                replacement = store.add_peer("new-laptop", public_key(23), ["users"])
                self.assertNotEqual(replacement["address"], old["address"])
                self.assertFalse(store.allowed(replacement["id"], server["id"], "tcp", 22))
                self.assertTrue(store.approve_peer(replacement["id"]))
                self.assertTrue(store.allowed(replacement["id"], server["id"], "tcp", 22))
                self.assertFalse(store.allowed(old["id"], server["id"], "tcp", 22))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

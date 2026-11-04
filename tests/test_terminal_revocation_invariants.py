"""Regression tests for terminal management-plane peer revocation.

These tests do not assert WireGuard tunnel teardown or packet filtering.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class TerminalRevocationTests(unittest.TestCase):
    def test_revocation_cannot_be_undone_or_reenrolled_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "vpn.db"
            store = VPNStore(database)
            try:
                source = store.add_peer("client", public_key(41), ["users"])
                target = store.add_peer("server", public_key(42), ["servers"])
                store.add_policy("users", "servers", "tcp", [22])
                self.assertTrue(store.approve_peer(source["id"]))
                self.assertTrue(store.approve_peer(target["id"]))
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 22))

                self.assertTrue(store.revoke_peer(source["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))
                self.assertFalse(store.approve_peer(source["id"]))
                self.assertFalse(store.revoke_peer(source["id"]))
                self.assertFalse(store.delete_peer(source["id"]))
                with self.assertRaises(ValidationError):
                    store.add_peer("replacement", public_key(41), ["users"])
                self.assertEqual(
                    [event["kind"] for event in store.events()].count("peer_revoked"), 1
                )
            finally:
                store.close()

            store = VPNStore(database)
            try:
                revoked = next(peer for peer in store.peers() if peer["id"] == source["id"])
                self.assertEqual(revoked["status"], "revoked")
                self.assertFalse(store.approve_peer(source["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))
                with self.assertRaises(ValidationError):
                    store.add_peer("replacement", public_key(41), ["users"])
                self.assertEqual(
                    [event["kind"] for event in store.events()].count("peer_revoked"), 1
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

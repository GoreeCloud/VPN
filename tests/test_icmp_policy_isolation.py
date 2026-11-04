"""Regression coverage for ICMP management-policy isolation (not packet enforcement)."""
import base64
import tempfile
import unittest
from pathlib import Path

from goreecloud_vpn.core import VPNStore


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class ICMPPolicyIsolationTests(unittest.TestCase):
    def test_directional_default_deny_and_immediate_revocation(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "vpn.sqlite3"
            store = VPNStore(db)
            try:
                source = store.add_peer("source", key(1), ["users"])
                target = store.add_peer("target", key(2), ["servers"])
                outsider = store.add_peer("outsider", key(3), ["guests"])
                ids = [p["id"] for p in (source, target, outsider)]

                # A policy must never authorize pending identities.
                rule = store.add_policy("users", "servers", "icmp", [])
                self.assertFalse(store.allowed(ids[0], ids[1], "icmp"))
                for peer_id in ids:
                    self.assertTrue(store.approve_peer(peer_id))

                self.assertTrue(store.allowed(ids[0], ids[1], "icmp"))
                self.assertFalse(store.allowed(ids[1], ids[0], "icmp"))
                self.assertFalse(store.allowed(ids[2], ids[1], "icmp"))
                self.assertFalse(store.allowed(ids[0], ids[2], "icmp"))
                self.assertFalse(store.allowed(ids[0], ids[0], "icmp"))
                self.assertFalse(store.allowed(ids[0], ids[1], "tcp", 22))
                self.assertFalse(store.allowed(ids[0], ids[1], "udp", 53))

                # Revocation is terminal and must invalidate the decision now.
                self.assertTrue(store.revoke_peer(ids[1]))
                self.assertFalse(store.allowed(ids[0], ids[1], "icmp"))
                self.assertFalse(store.approve_peer(ids[1]))
                self.assertFalse(store.allowed(ids[0], ids[1], "icmp"))
            finally:
                store.close()

            # A reopened database must not resurrect access.
            reopened = VPNStore(db)
            try:
                self.assertFalse(reopened.allowed(ids[0], ids[1], "icmp"))
                self.assertTrue(reopened.delete_policy(rule["id"]))
                self.assertFalse(reopened.allowed(ids[0], ids[1], "icmp"))
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()

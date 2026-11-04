"""Fail-closed approval gating for offline WireGuard adjacency previews.

These tests do not establish or enforce network connectivity.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.plan import build_peer_plan, render_wireguard_peer_fragments


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class PlanApprovalGatingTests(unittest.TestCase):
    def test_remote_peer_never_appears_before_explicit_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                local = store.add_peer("laptop", public_key(61), ["users"])
                remote = store.add_peer("server", public_key(62), ["servers"])
                store.add_policy("users", "servers", "tcp", [22])
                self.assertTrue(store.approve_peer(local["id"]))

                # A matching allow rule alone must not expose a pending peer.
                pending_plan = build_peer_plan(store, local["id"])
                self.assertEqual(pending_plan["peers"], [])
                self.assertNotIn("[Peer]", render_wireguard_peer_fragments(pending_plan))

                self.assertTrue(store.approve_peer(remote["id"]))
                approved_plan = build_peer_plan(store, local["id"])
                self.assertEqual([p["peer_id"] for p in approved_plan["peers"]], [remote["id"]])
                self.assertIn("[Peer]", render_wireguard_peer_fragments(approved_plan))

                # Revocation must remove adjacency, not just deny access checks.
                self.assertTrue(store.revoke_peer(remote["id"]))
                revoked_plan = build_peer_plan(store, local["id"])
                self.assertEqual(revoked_plan["peers"], [])
                self.assertNotIn("[Peer]", render_wireguard_peer_fragments(revoked_plan))
                self.assertFalse(store.approve_peer(remote["id"]))
            finally:
                store.close()

    def test_revoked_local_peer_cannot_generate_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                local = store.add_peer("laptop", public_key(63), ["users"])
                remote = store.add_peer("server", public_key(64), ["servers"])
                store.add_policy("users", "servers", "udp", [53])
                self.assertTrue(store.approve_peer(local["id"]))
                self.assertTrue(store.approve_peer(remote["id"]))
                self.assertEqual(len(build_peer_plan(store, local["id"])["peers"]), 1)
                self.assertTrue(store.revoke_peer(local["id"]))
                with self.assertRaises(ValidationError):
                    build_peer_plan(store, local["id"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

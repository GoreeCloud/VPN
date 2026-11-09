"""Ensure migrated unit fixtures cannot silently bypass X25519 proof gates."""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from proven_peer_fixture import key, prove_peer, prove_and_approve


class GenuineTestProofFixtureChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.temp.name) / "vpn.db")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_approval_stays_pending_until_a_real_fixture_proof(self):
        peer = self.store.add_peer("fixturepeer", key(201), ["users"])
        self.assertFalse(self.store.approve_peer(peer["id"]))
        self.assertTrue(prove_peer(self.store, peer))
        self.assertEqual(self.store.peers()[0]["status"], "pending")
        self.assertTrue(self.store.approve_peer(peer["id"]))
        self.assertEqual(self.store.peers()[0]["status"], "approved")
        self.assertIn("peer_key_proved", [r["kind"] for r in self.store.events()])

    def test_unowned_private_key_cannot_use_fixture_approval(self):
        alien_pub = base64.b64encode(bytes([144]) * 32).decode("ascii")
        peer = self.store.add_peer("unknown-private", alien_pub, ["users"])
        with self.assertRaises(AssertionError):
            prove_and_approve(self.store, peer)
        self.assertFalse(self.store.approve_peer(peer["id"]))
        self.assertEqual(self.store.peers()[0]["status"], "pending")

    def test_revoked_peer_stays_revoked_even_if_fixture_knows_private(self):
        peer = self.store.add_peer("revoked", key(202), ["users"])
        self.assertTrue(prove_and_approve(self.store, peer))
        self.assertTrue(self.store.revoke_peer(peer["id"]))
        with self.assertRaises(ValidationError):
            prove_peer(self.store, peer)
        self.assertFalse(self.store.approve_peer(peer["id"]))


if __name__ == "__main__":
    unittest.main()

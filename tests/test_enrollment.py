"""Key-possession verification and fail-closed upgrade regressions."""
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.enrollment import ProofChallenges, device_proof


def identity(seed):
    private = X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, base64.b64encode(raw).decode("ascii")


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = VPNStore(self.path)
        self.private, public = identity(70)
        self.peer = self.store.add_peer("proofdevice", public, ["devices"])
        self.manager = ProofChallenges(self.store)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_correct_device_proves_possession_before_admin_approval(self):
        self.assertFalse(self.store.approve_peer(self.peer["id"]))
        challenge = self.manager.issue(self.peer["id"])
        self.assertNotIn("private_key", json.dumps(challenge).lower())
        self.assertEqual(challenge["expires_in_seconds"], 120)
        proof = device_proof(self.private, challenge)
        self.assertTrue(self.manager.verify(self.peer["id"], challenge["challenge_id"], proof))
        self.assertFalse(self.manager.verify(self.peer["id"], challenge["challenge_id"], proof))
        self.assertTrue(self.store.approve_peer(self.peer["id"]))
        self.assertEqual(self.store.dns_records()[0]["name"], "proofdevice.vpn.internal")
        self.assertEqual([row["kind"] for row in self.store.events()], [
            "peer_approved", "peer_key_proved", "peer_registered"
        ])

    def test_wrong_key_and_invalid_proof_are_rejected_and_consumed(self):
        challenge = self.manager.issue(self.peer["id"])
        wrong_key, _ = identity(71)
        with self.assertRaises(ValidationError):
            device_proof(wrong_key, challenge)
        false_proof = base64.b64encode(b"X" * 32).decode("ascii")
        self.assertFalse(self.manager.verify(self.peer["id"], challenge["challenge_id"], false_proof))
        real_proof = device_proof(self.private, challenge)
        self.assertFalse(self.manager.verify(self.peer["id"], challenge["challenge_id"], real_proof))
        self.assertFalse(self.store.approve_peer(self.peer["id"]))
        renewed = self.manager.issue(self.peer["id"])
        self.assertTrue(self.manager.verify(
            self.peer["id"], renewed["challenge_id"], device_proof(self.private, renewed)
        ))

    def test_transcript_tampering_is_rejected(self):
        challenge = self.manager.issue(self.peer["id"])
        changed = dict(challenge)
        changed["peer_id"] = "different-peer"
        proof = device_proof(self.private, changed)
        self.assertFalse(self.manager.verify(self.peer["id"], challenge["challenge_id"], proof))
        self.assertFalse(self.store.approve_peer(self.peer["id"]))

    def test_short_lifetime_and_one_challenge_per_peer(self):
        clock = [5.0]
        manager = ProofChallenges(self.store, ttl_seconds=3, clock=lambda: clock[0])
        first = manager.issue(self.peer["id"])
        replacement = manager.issue(self.peer["id"])
        self.assertFalse(manager.verify(
            self.peer["id"], first["challenge_id"], device_proof(self.private, first)
        ))
        clock[0] = 9.0
        self.assertFalse(manager.verify(
            self.peer["id"], replacement["challenge_id"], device_proof(self.private, replacement)
        ))
        self.assertFalse(self.store.approve_peer(self.peer["id"]))

    def test_approval_requires_recent_proof(self):
        self.assertTrue(self.store.record_device_proof(self.peer["id"], self.peer["public_key"]))
        old = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "UPDATE peers SET proof_verified_at=? WHERE id=?", (old, self.peer["id"])
            )
        self.assertFalse(self.store.approve_peer(self.peer["id"]))
        challenge = self.manager.issue(self.peer["id"])
        self.assertTrue(self.manager.verify(
            self.peer["id"], challenge["challenge_id"], device_proof(self.private, challenge)
        ))
        self.assertTrue(self.store.approve_peer(self.peer["id"]))

    def test_revoked_peer_cannot_start_or_finish_a_challenge(self):
        challenge = self.manager.issue(self.peer["id"])
        self.assertTrue(self.store.revoke_peer(self.peer["id"]))
        self.assertFalse(self.manager.verify(
            self.peer["id"], challenge["challenge_id"], device_proof(self.private, challenge)
        ))
        with self.assertRaises(ValidationError):
            self.manager.issue(self.peer["id"])
        self.assertFalse(self.store.approve_peer(self.peer["id"]))

    def test_reject_low_order_key_for_x25519(self):
        low_order_key = base64.b64encode(b"\x01" + b"\x00" * 31).decode("ascii")
        peer = self.store.add_peer("badcurve", low_order_key, ["devices"])
        with self.assertRaises(ValidationError):
            self.manager.issue(peer["id"])

    def test_previous_approved_records_are_demoted_on_migration(self):
        self.store.close()
        self.path.unlink()
        db = sqlite3.connect(self.path)
        db.execute("""CREATE TABLE peers (
            id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
            public_key TEXT UNIQUE NOT NULL, address TEXT UNIQUE NOT NULL,
            endpoint TEXT, groups TEXT NOT NULL, created TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        )""")
        db.execute("INSERT INTO peers VALUES (?,?,?,?,?,?,?,?)", (
            "previously-approved", "previous", self.peer["public_key"],
            "10.234.12.10", None, '["devices"]',
            datetime.now(timezone.utc).isoformat(), "approved"
        ))
        db.commit()
        db.close()
        self.store = VPNStore(self.path)
        self.manager = ProofChallenges(self.store)
        prior = self.store.peers()[0]
        self.assertEqual(prior["status"], "pending")
        self.assertIsNone(prior["proof_verified_at"])
        self.assertEqual(self.store.dns_records(), [])
        self.assertFalse(self.store.approve_peer(prior["id"]))


if __name__ == "__main__":
    unittest.main()

"""Security regression tests for pending/approved/revoked device lifecycle."""
import base64
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class ApprovalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "vpn.db"
        self.store = VPNStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def approve(self, peer):
        # Internal store-only fixture; HTTP tests verify actual key possession.
        self.assertTrue(self.store.record_device_proof(peer["id"], peer["public_key"]))
        self.assertTrue(self.store.approve_peer(peer["id"]))

    def test_pending_approval_and_irreversible_revocation(self):
        src = self.store.add_peer("sender", key(24), ["team"])
        dst = self.store.add_peer("receiver", key(25), ["services"])
        self.assertEqual(src["status"], "pending")
        self.assertEqual(dst["status"], "pending")
        self.store.add_policy("team", "services", "tcp", [443])
        self.assertFalse(self.store.allowed(src["id"], dst["id"], "tcp", 443))
        self.assertEqual(self.store.dns_records(), [])
        self.approve(src)
        self.assertFalse(self.store.allowed(src["id"], dst["id"], "tcp", 443))
        self.approve(dst)
        self.assertTrue(self.store.allowed(src["id"], dst["id"], "tcp", 443))
        self.assertEqual(len(self.store.dns_records()), 2)
        self.assertTrue(self.store.revoke_peer(src["id"]))
        self.assertFalse(self.store.allowed(src["id"], dst["id"], "tcp", 443))
        self.assertEqual(len(self.store.dns_records()), 1)
        self.assertFalse(self.store.approve_peer(src["id"]))
        self.assertFalse(self.store.revoke_peer(src["id"]))
        with self.assertRaises(ValidationError):
            self.store.add_peer("newsender", key(24), ["team"])

        self.store.close()
        self.store = VPNStore(self.path)
        self.assertEqual(
            next(p["status"] for p in self.store.peers() if p["id"] == src["id"]),
            "revoked"
        )
        self.assertFalse(self.store.approve_peer(src["id"]))

    def test_local_event_history_omits_public_keys(self):
        peer = self.store.add_peer("example", key(26), ["team"])
        self.approve(peer)
        self.store.delete_peer(peer["id"])
        events = self.store.events()
        self.assertEqual([e["kind"] for e in events], [
            "peer_revoked", "peer_approved", "peer_key_proved", "peer_registered"
        ])
        self.assertEqual([e["peer_id"] for e in events], [peer["id"]] * 4)
        self.assertNotIn(key(26), json.dumps(events))

    def test_legacy_peer_records_migrate_to_pending(self):
        self.store.close()
        self.path.unlink()
        db = sqlite3.connect(self.path)
        db.execute("""CREATE TABLE peers (
            id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
            public_key TEXT UNIQUE NOT NULL, address TEXT UNIQUE NOT NULL,
            endpoint TEXT, groups TEXT NOT NULL, created TEXT NOT NULL)""")
        db.execute("INSERT INTO peers VALUES (?,?,?,?,?,?,?)",
                   ("legacy-peer", "legacy", key(27), "10.234.12.10",
                    None, '["team"]', "2026-11-03T00:00:00+00:00"))
        db.commit()
        db.close()
        self.store = VPNStore(self.path)
        self.assertEqual(self.store.peers()[0]["status"], "pending")
        self.assertEqual(self.store.dns_records(), [])
        self.assertFalse(self.store.allowed("legacy-peer", "legacy-peer", "tcp", 443))


if __name__ == "__main__":
    unittest.main()

import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class VPNStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "vpn.db"
        self.store = VPNStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_default_deny_and_allowlist(self):
        a = self.store.add_peer("alice", key(1), ["users"])
        b = self.store.add_peer("server", key(2), ["infra"])
        self.assertEqual(a["address"], "10.234.12.10")
        self.assertEqual(b["address"], "10.234.12.11")
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 22))
        rule = self.store.add_policy("users", "infra", "tcp", [22])
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 22))
        self.assertTrue(self.store.approve_peer(a["id"]))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 22))
        self.assertTrue(self.store.approve_peer(b["id"]))
        self.assertTrue(self.store.allowed(a["id"], b["id"], "tcp", 22))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 443))
        self.assertFalse(self.store.allowed(b["id"], a["id"], "tcp", 22))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "udp", 22))
        self.assertTrue(self.store.delete_policy(rule["id"]))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 22))

    def test_deleted_policy_stays_denied_after_store_restart(self):
        """A removed management allow rule must not reappear after SQLite reopen."""
        source = self.store.add_peer("client", key(21), ["users"])
        target = self.store.add_peer("service", key(22), ["infra"])
        self.assertTrue(self.store.approve_peer(source["id"]))
        self.assertTrue(self.store.approve_peer(target["id"]))
        forward = self.store.add_policy("users", "infra", "tcp", [443])
        reverse = self.store.add_policy("infra", "users", "tcp", [443])
        self.assertTrue(self.store.allowed(source["id"], target["id"], "tcp", 443))
        self.assertTrue(self.store.allowed(target["id"], source["id"], "tcp", 443))

        self.assertTrue(self.store.delete_policy(forward["id"]))
        self.assertTrue(self.store.delete_policy(reverse["id"]))
        self.store.close()
        self.store = VPNStore(self.path)

        self.assertFalse(self.store.allowed(source["id"], target["id"], "tcp", 443))
        self.assertFalse(self.store.allowed(target["id"], source["id"], "tcp", 443))
        self.assertFalse(self.store.allowed(source["id"], target["id"], "tcp", 444))
        self.assertEqual(
            {peer["status"] for peer in self.store.peers()},
            {"approved"},
        )

    def test_revocation_remains_denied_after_store_restart(self):
        """Revoked identity stays denied even when its allow rules still exist."""
        source = self.store.add_peer("client", key(31), ["users"])
        target = self.store.add_peer("service", key(32), ["infra"])
        self.assertTrue(self.store.approve_peer(source["id"]))
        self.assertTrue(self.store.approve_peer(target["id"]))
        self.store.add_policy("users", "infra", "tcp", [443])
        self.store.add_policy("infra", "users", "tcp", [443])
        self.assertTrue(self.store.allowed(source["id"], target["id"], "tcp", 443))
        self.assertTrue(self.store.allowed(target["id"], source["id"], "tcp", 443))

        self.assertTrue(self.store.revoke_peer(target["id"]))
        self.store.close()
        self.store = VPNStore(self.path)

        for left, right in ((source["id"], target["id"]),
                            (target["id"], source["id"])):
            with self.subTest(source=left):
                decision = self.store.explain_access(left, right, "tcp", 443)
                self.assertFalse(decision["allowed"])
                self.assertEqual(decision["reason"], "peer_not_approved")
                self.assertEqual(decision["matching_policy_ids"], [])
                self.assertFalse(decision["data_plane_enforced"])
        self.assertFalse(self.store.approve_peer(target["id"]))
        self.assertEqual(
            {peer["status"] for peer in self.store.peers()},
            {"approved", "revoked"},
        )

    def test_revoked_key_tombstone_survives_restart(self):
        """A revoked key cannot be re-enrolled after reopening the store."""
        original = self.store.add_peer("retired", key(41), ["users"])
        self.assertTrue(self.store.approve_peer(original["id"]))
        self.assertTrue(self.store.revoke_peer(original["id"]))
        self.store.close()
        self.store = VPNStore(self.path)

        with self.assertRaises(ValidationError):
            self.store.add_peer("replacement", key(41), ["users"])
        self.assertFalse(self.store.approve_peer(original["id"]))
        peers = self.store.peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["status"], "revoked")
        self.assertEqual(peers[0]["public_key"], key(41))

    def test_invalid_input_and_duplicate_keys(self):
        with self.assertRaises(ValidationError):
            self.store.add_peer("invalid name", key(1), [])
        with self.assertRaises(ValidationError):
            self.store.add_peer("alice", "bad", [])
        self.store.add_peer("alice", key(1), ["users"])
        with self.assertRaises(ValidationError):
            self.store.add_peer("another", key(1), [])
        with self.assertRaises(ValidationError):
            self.store.add_peer("alice", key(3), [])
        with self.assertRaises(ValidationError):
            self.store.add_policy("users", "infra", "tcp", [True])
        with self.assertRaises(ValidationError):
            self.store.add_policy("users", "infra", "udp", [])
        with self.assertRaises(ValidationError):
            self.store.add_policy("users", "infra", "icmp", [1])

    def test_revocation_dns_and_persistence(self):
        a = self.store.add_peer("alice", key(4), ["users"])
        b = self.store.add_peer("server", key(5), ["infra"])
        self.assertEqual(len(self.store.dns_records()), 0)
        self.store.approve_peer(a["id"])
        self.store.approve_peer(b["id"])
        self.assertEqual(len(self.store.dns_records()), 2)
        self.store.add_policy("users", "infra", "icmp", [])
        self.assertTrue(self.store.allowed(a["id"], b["id"], "icmp"))
        self.assertTrue(self.store.delete_peer(b["id"]))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "icmp"))
        self.store.close()
        self.store = VPNStore(self.path)
        self.assertEqual(len(self.store.peers()), 2)
        self.assertEqual({peer["status"] for peer in self.store.peers()}, {"approved", "revoked"})
        self.assertEqual(len(self.store.dns_records()), 1)

    def test_reject_non_rfc1918_subnets(self):
        for network in ("127.0.0.0/24", "169.254.20.0/24", "192.0.2.0/24"):
            with self.subTest(network=network), self.assertRaises(ValidationError):
                VPNStore(self.path.parent / (network.split(".")[0] + ".db"), subnet=network)

    def test_ipv6_endpoint_validation(self):
        self.store.add_peer("server", key(6), [], "[2001:db8::1]:51820")
        with self.assertRaises(ValidationError):
            self.store.add_peer("bad", key(7), [], "[gggg::1]:51820")


if __name__ == "__main__":
    unittest.main()

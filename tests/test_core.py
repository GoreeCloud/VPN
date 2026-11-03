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
        self.assertTrue(self.store.allowed(a["id"], b["id"], "tcp", 22))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 443))
        self.assertFalse(self.store.allowed(b["id"], a["id"], "tcp", 22))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "udp", 22))
        self.assertTrue(self.store.delete_policy(rule["id"]))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "tcp", 22))

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
        self.assertEqual(len(self.store.dns_records()), 2)
        self.store.add_policy("users", "infra", "icmp", [])
        self.assertTrue(self.store.allowed(a["id"], b["id"], "icmp"))
        self.assertTrue(self.store.delete_peer(b["id"]))
        self.assertFalse(self.store.allowed(a["id"], b["id"], "icmp"))
        self.store.close()
        self.store = VPNStore(self.path)
        self.assertEqual(len(self.store.peers()), 1)

    def test_ipv6_endpoint_validation(self):
        self.store.add_peer("server", key(6), [], "[2001:db8::1]:51820")
        with self.assertRaises(ValidationError):
            self.store.add_peer("bad", key(7), [], "[gggg::1]:51820")


if __name__ == "__main__":
    unittest.main()

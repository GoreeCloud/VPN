"""Regression coverage for fail-closed management policy validation.

These tests exercise stored decisions only, not packet-level VPN enforcement.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class PolicyValidationAtomicityTests(unittest.TestCase):
    def test_invalid_rules_do_not_mutate_policy_store_or_grant_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.db"
            store = VPNStore(path)
            try:
                source = store.add_peer("client", public_key(41), ["users"])
                target = store.add_peer("server", public_key(42), ["servers"])
                self.assertTrue(store.approve_peer(source["id"]))
                self.assertTrue(store.approve_peer(target["id"]))
                invalid = [
                    ("users", "servers", "tcp", [True]),
                    ("users", "servers", "udp", [False]),
                    ("users", "servers", "tcp", [0]),
                    ("users", "servers", "tcp", [65536]),
                    ("users", "servers", "tcp", [22, "443"]),
                    ("users", "servers", "tcp", []),
                    ("users", "servers", "icmp", [22]),
                    ("users", "servers", "sctp", [22]),
                    ("bad group", "servers", "tcp", [22]),
                    ("users", "bad group", "tcp", [22]),
                    ("users", "servers", "tcp", [22] * 65),
                ]
                for rule in invalid:
                    with self.subTest(rule=rule):
                        before = store.policies()
                        with self.assertRaises(ValidationError):
                            store.add_policy(*rule)
                        self.assertEqual(store.policies(), before)
                        self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))
                        self.assertFalse(store.allowed(source["id"], target["id"], "udp", 22))
                        self.assertFalse(store.allowed(source["id"], target["id"], "icmp"))

                store.close()
                store = VPNStore(path)
                self.assertEqual(store.policies(), [])
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))

                rule = store.add_policy("users", "servers", "tcp", [443, 22, 22])
                self.assertEqual(rule["ports"], [22, 443])
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 22))
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 443))
                self.assertFalse(store.allowed(source["id"], target["id"], "udp", 22))
                self.assertFalse(store.allowed(target["id"], source["id"], "tcp", 22))
                self.assertTrue(store.delete_policy(rule["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))
                store.close()
                store = VPNStore(path)
                self.assertEqual(store.policies(), [])
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 443))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

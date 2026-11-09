import base64
import os
import sqlite3
import stat
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

    def test_untrusted_storage_links_and_special_files_fail_closed(self):
        base = Path(self.temp.name)
        target = base / "protected-source"
        target.write_bytes(b"keep-original-private-bytes")
        target.chmod(0o600)
        (base / "symlink.db").symlink_to(target)
        os.link(target, base / "hardlink.db")
        os.mkfifo(base / "fifo.db", 0o600)
        (base / "directory.db").mkdir(mode=0o700)
        for candidate in ("symlink.db", "hardlink.db", "fifo.db",
                          "directory.db"):
            with self.subTest(candidate=candidate), self.assertRaises(ValidationError):
                VPNStore(base / candidate)
        self.assertEqual(target.read_bytes(), b"keep-original-private-bytes")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_preexisting_state_keeps_permissions_and_requires_manual_repair(self):
        base = Path(self.temp.name)
        legacy = base / "legacy-readable.db"
        with sqlite3.connect(legacy) as connection:
            connection.execute("CREATE TABLE kept (value TEXT)")
            connection.execute("INSERT INTO kept VALUES ('original')")
        legacy.chmod(0o644)
        with self.assertRaises(ValidationError):
            VPNStore(legacy)
        self.assertEqual(stat.S_IMODE(legacy.stat().st_mode), 0o644,
                         "rejection must not chmod a preexisting file")
        legacy.chmod(0o600)
        store = VPNStore(legacy)
        try:
            self.assertEqual(store.db.execute("SELECT value FROM kept").fetchone()[0],
                             "original")
        finally:
            store.close()

    def test_public_or_symlinked_database_parent_is_not_repaired(self):
        base = Path(self.temp.name)
        public = base / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(ValidationError):
            VPNStore(public / "state.db")
        self.assertFalse((public / "state.db").exists())
        self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o755)

        linked = base / "linked-dir"
        linked.symlink_to(base, target_is_directory=True)
        with self.assertRaises(ValidationError):
            VPNStore(linked / "state.db")
        self.assertFalse((base / "state.db").exists())

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

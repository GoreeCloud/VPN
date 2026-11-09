"""Offline key-to-/32 binding manifest security and determinism tests."""
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from proven_peer_fixture import key, prove_and_approve
from goreecloud_vpn.identity_binding import (
    BINDING_SCHEMA, build_key_address_binding_intent,
)




class KeyAddressBindingManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.temp.name) / "state.db", subnet="10.77.0.0/24")
        self.a = self.store.add_peer("source", key(91), ["users"], "192.0.2.50:51820")
        self.b = self.store.add_peer("server", key(92), ["services"])
        self.c = self.store.add_peer("unapproved", key(93), ["guest"])

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def manifest(self, peers):
        return build_key_address_binding_intent(SimpleNamespace(
            network=ipaddress.ip_network("10.77.0.0/24"),
            snapshot=lambda: (peers, []),
        ))

    def test_default_is_empty_and_not_active(self):
        record = build_key_address_binding_intent(self.store)
        self.assertEqual(record["schema"], BINDING_SCHEMA)
        self.assertEqual(record["bindings"], [])
        self.assertEqual(record["binding_count"], 0)
        self.assertFalse(record["key_possession_verified"])
        self.assertFalse(record["active_wireguard_state_verified"])
        self.assertFalse(record["snapshot_sha256_is_authenticated"])
        self.assertFalse(record["applied"])
        self.assertFalse(record["data_plane_enforced"])

    def test_approved_only_deterministic_host_prefixes(self):
        prove_and_approve(self.store, self.a)
        prove_and_approve(self.store, self.b)
        before = self.store.snapshot()
        first = build_key_address_binding_intent(self.store)
        second = build_key_address_binding_intent(self.store)
        self.assertEqual(first, second)
        self.assertEqual(first["binding_count"], 2)
        self.assertEqual(first["bindings"][0]["allowed_ips"], ["10.77.0.10/32"])
        self.assertEqual(first["bindings"][1]["allowed_ips"], ["10.77.0.11/32"])
        self.assertEqual(first["bindings"][0]["public_key"], key(91))
        self.assertEqual(first["bindings"][0]["endpoint"], "192.0.2.50:51820")
        self.assertFalse(any("private_key" in b for b in first["bindings"]))
        self.assertEqual(len(first["snapshot_sha256"]), 64)
        self.assertEqual(self.store.snapshot(), before)

    def test_revocation_changes_plan_and_does_not_mutate_state(self):
        prove_and_approve(self.store, self.a)
        prove_and_approve(self.store, self.b)
        before = build_key_address_binding_intent(self.store)
        self.assertTrue(self.store.revoke_peer(self.b["id"]))
        after = build_key_address_binding_intent(self.store)
        self.assertEqual(after["binding_count"], 1)
        self.assertNotEqual(before["snapshot_sha256"], after["snapshot_sha256"])
        self.assertNotIn(key(92), json.dumps(after))

    def test_duplicate_identity_or_address_fails_closed(self):
        prove_and_approve(self.store, self.a)
        prove_and_approve(self.store, self.b)
        peers = [p for p in self.store.peers() if p["status"] == "approved"]
        for field in ("id", "public_key", "address"):
            with self.subTest(field=field):
                changed = [dict(p) for p in peers]
                changed[1][field] = changed[0][field]
                with self.assertRaises(ValidationError):
                    self.manifest(changed)

    def test_invalid_approved_keys_and_addresses_fail_closed(self):
        prove_and_approve(self.store, self.a)
        peers = [p for p in self.store.peers() if p["status"] == "approved"]
        for field, bad in (
            ("public_key", "not-a-key"),
            ("address", "8.8.8.8"),
            ("address", "10.77.0.0"),
            ("address", "10.77.0.255"),
            ("address", "127.0.0.1"),
            ("endpoint", "http://untrusted.example:9999"),
            ("status", "trusted"),
        ):
            with self.subTest(field=field, bad=bad):
                changed = [dict(peers[0])]
                changed[0][field] = bad
                with self.assertRaises(ValidationError):
                    self.manifest(changed)

    def test_pending_and_revoked_are_not_binding_targets(self):
        self.assertTrue(self.store.revoke_peer(self.c["id"]))
        self.assertTrue(prove_and_approve(self.store, self.a))
        record = build_key_address_binding_intent(self.store)
        self.assertEqual(record["binding_count"], 1)
        self.assertEqual(record["bindings"][0]["peer_id"], self.a["id"])
        self.assertNotIn(key(93), json.dumps(record))


if __name__ == "__main__":
    unittest.main()

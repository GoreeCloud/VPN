"""Single-generation offline preflight tests: no kernel or networking invoked."""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.agent_preflight import (
    SCHEMA, build_offline_ingress_preflight,
)


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode("ascii")


class OfflineAgentPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = VPNStore(Path(self.temp.name) / "db", subnet="10.77.0.0/24")
        self.source = self.db.add_peer("source", key(110), ["users"])
        self.target = self.db.add_peer("target", key(111), ["services"])
        self.stranger = self.db.add_peer("stranger", key(112), ["guests"])
        self.assertTrue(self.db.approve_peer(self.source["id"]))
        self.assertTrue(self.db.approve_peer(self.target["id"]))
        self.valid_readback = key(110) + "\t10.77.0.10/32\n"

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def compile(self, readback):
        return build_offline_ingress_preflight(
            self.db, self.target["id"], readback, interface="wgB"
        )

    def test_policy_scoped_exact_match_is_unapplied(self):
        self.db.add_policy("users", "services", "tcp", [443])
        before = self.db.snapshot()
        report = self.compile(self.valid_readback)
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["source_peer_ids"], [self.source["id"]])
        self.assertEqual(report["allowed_source_count"], 1)
        self.assertTrue(report["single_snapshot_compiled"])
        self.assertTrue(report["public_text_comparison"]["text_matches_selected_intent"])
        self.assertEqual(report["firewall_preview"]["allow_rule_count"], 1)
        self.assertFalse(report["candidate_sha256_is_authenticated"])
        self.assertFalse(report["kernel_readback_authenticated"])
        self.assertFalse(report["agent_invoked"])
        self.assertFalse(report["data_plane_enforced"])
        self.assertFalse(report["production_ready"])
        self.assertFalse(report["applied"])
        self.assertEqual(self.db.snapshot(), before)

    def test_empty_policy_requires_no_installed_inbound_peers(self):
        report = self.compile("")
        self.assertEqual(report["source_peer_ids"], [])
        self.assertEqual(report["firewall_preview"]["allow_rule_count"], 0)
        with self.assertRaises(ValidationError):
            self.compile(self.valid_readback)

    def test_reversed_policy_does_not_authorize_incoming_peer(self):
        self.db.add_policy("services", "users", "icmp", [])
        self.assertEqual(self.compile("")["source_peer_ids"], [])
        with self.assertRaises(ValidationError):
            self.compile(self.valid_readback)

    def test_missing_unknown_and_wrong_ip_refuse_bundle(self):
        self.db.add_policy("users", "services", "tcp", [443])
        for text in (
            "",
            key(112) + "\t10.77.0.12/32\n",
            key(110) + "\t10.77.0.12/32\n",
            self.valid_readback + key(112) + "\t10.77.0.12/32\n",
            key(110) + "\t10.77.0.10/24\n",
        ):
            with self.subTest(text=text), self.assertRaises(ValidationError):
                self.compile(text)

    def test_pending_peer_never_bypasses_approval(self):
        self.db.add_policy("guests", "services", "udp", [53])
        self.assertEqual(self.compile("")["source_peer_ids"], [])
        self.assertTrue(self.db.approve_peer(self.stranger["id"]))
        report = self.compile(key(112) + "\t10.77.0.12/32\n")
        self.assertEqual(report["source_peer_ids"], [self.stranger["id"]])

    def test_revocation_invalidates_prior_source_and_fingerprint(self):
        self.db.add_policy("users", "services", "icmp", [])
        prior = self.compile(self.valid_readback)
        self.assertTrue(self.db.revoke_peer(self.source["id"]))
        after = self.compile("")
        self.assertNotEqual(prior["candidate_sha256"], after["candidate_sha256"])
        with self.assertRaises(ValidationError):
            self.compile(self.valid_readback)

    def test_one_snapshot_call_only_even_with_multiple_compilers(self):
        self.db.add_policy("users", "services", "tcp", [443])

        class SnapshotCounter:
            def __init__(self, db):
                self.db, self.network, self.calls = db, db.network, 0

            def snapshot(self):
                self.calls += 1
                if self.calls != 1:
                    raise AssertionError("multiple generations mixed")
                return self.db.snapshot()

        counter = SnapshotCounter(self.db)
        result = build_offline_ingress_preflight(
            counter, self.target["id"], self.valid_readback, interface="wgB"
        )
        self.assertEqual(counter.calls, 1)
        self.assertEqual(result["allowed_source_count"], 1)

    def test_same_snapshot_is_deterministic_and_policy_change_updates_digest(self):
        self.db.add_policy("users", "services", "tcp", [443])
        first = self.compile(self.valid_readback)
        self.assertEqual(first, self.compile(self.valid_readback))
        self.db.add_policy("users", "services", "udp", [53])
        after = self.compile(self.valid_readback)
        self.assertNotEqual(first["candidate_sha256"], after["candidate_sha256"])

    def test_target_pending_or_revoked_never_generates_bundle(self):
        self.db.add_policy("users", "services", "tcp", [443])
        self.assertTrue(self.db.revoke_peer(self.target["id"]))
        with self.assertRaises(ValidationError):
            self.compile(self.valid_readback)

    def test_bad_policy_or_duplicate_approved_key_fails_closed(self):
        self.db.add_policy("users", "services", "tcp", [443])
        with self.db.lock, self.db.db:
            self.db.db.execute(
                "UPDATE policies SET protocol='raw' WHERE target='services'"
            )
        with self.assertRaises(ValidationError):
            self.compile(self.valid_readback)

    def test_malformed_interface_rejected_without_result(self):
        self.db.add_policy("users", "services", "icmp", [])
        with self.assertRaises(ValidationError):
            build_offline_ingress_preflight(
                self.db, self.target["id"], self.valid_readback, interface='wgB";drop'
            )


if __name__ == "__main__":
    unittest.main()

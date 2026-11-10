"""Offline peer planning tests; no network capabilities required."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.plan import build_peer_plan, render_wireguard_peer_fragments, PLAN_SCHEMA


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class PeerPlanningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.temp.name) / "state.db")
        self.client = self.store.add_peer("client", key(30), ["users"])
        self.server = self.store.add_peer(
            "server", key(31), ["services"], "192.0.2.30:51820"
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_peer_plan_uses_one_consistent_snapshot_not_separate_reads(self):
        self.store.add_policy("users", "services", "tcp", [443])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        good_peers, _ = self.store.snapshot()

        class MixedGenerationStore:
            # These separate reads previously advertised an authorized
            # adjacency after the source peer was already revoked.
            def peers(self):
                return good_peers

            def policies(self):
                return [{"source": "users", "target": "services",
                         "protocol": "tcp", "ports": [443]}]

            def snapshot(self):
                current = deepcopy(good_peers)
                for peer in current:
                    if peer["id"] == self_server_id:
                        peer["status"] = "revoked"
                return current, []

        self_server_id = self.server["id"]
        plan = build_peer_plan(MixedGenerationStore(), self.client["id"])
        self.assertEqual(plan["peers"], [])
        self.assertFalse(plan["wireguard_tunnels_active"])

    def test_real_store_uses_bounded_sql_snapshot_not_separate_reads(self):
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        with patch.object(self.store, "snapshot", side_effect=AssertionError(
            "offline plan must use SQL-bounded atomic source"
        )), patch.object(self.store, "peers", side_effect=AssertionError(
            "offline plan must never separately read peers"
        )), patch.object(self.store, "policies", side_effect=AssertionError(
            "offline plan must never separately read policies"
        )):
            plan = build_peer_plan(self.store, self.client["id"])
        self.assertEqual(plan["peers"], [])
        self.assertFalse(self.store.db.in_transaction)
        with patch("goreecloud_vpn.plan.MAX_PLAN_PEERS", 1):
            with self.assertRaisesRegex(ValidationError, "bounded input limits"):
                build_peer_plan(self.store, self.client["id"])
        self.assertFalse(self.store.db.in_transaction)

    def test_plan_refuses_nested_sql_snapshot_without_rolling_back_caller(self):
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        self.store.db.execute("BEGIN")
        try:
            with self.assertRaises(ValidationError):
                build_peer_plan(self.store, self.client["id"])
            self.assertTrue(self.store.db.in_transaction)
        finally:
            self.store.db.execute("ROLLBACK")
        self.assertFalse(self.store.db.in_transaction)
        self.assertFalse(build_peer_plan(self.store, self.client["id"])["peers"])

    def test_legacy_atomic_snapshot_still_enforces_resource_caps(self):
        class Synthetic:
            def __init__(self, peers, policies):
                self._peers, self._policies = peers, policies
                self.calls = 0

            def snapshot(self):
                self.calls += 1
                return self._peers, self._policies

        good_peers, good_policies = self.store.snapshot()
        from goreecloud_vpn.plan import (
            MAX_PLAN_PEERS, MAX_PLAN_POLICIES, MAX_PLAN_EVALUATIONS,
        )
        both = int(MAX_PLAN_EVALUATIONS ** 0.5) + 1
        cases = [
            (tuple(good_peers), good_policies),
            (good_peers, tuple(good_policies)),
            (good_peers[:1] * (MAX_PLAN_PEERS + 1), good_policies),
            (good_peers, [None] * (MAX_PLAN_POLICIES + 1)),
            (good_peers[:1] * both, [None] * both),
        ]
        for peers, policies in cases:
            with self.subTest(peer_count=len(peers), policy_count=len(policies)):
                source = Synthetic(peers, policies)
                with self.assertRaisesRegex(ValidationError, "bounded input limits"):
                    build_peer_plan(source, self.client["id"])
                self.assertEqual(source.calls, 1)

    def test_unapproved_local_peer_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_peer_plan(self.store, self.client["id"])

    def test_default_deny_excludes_unrelated_peers(self):
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        plan = build_peer_plan(self.store, self.client["id"])
        self.assertEqual(plan["schema"], PLAN_SCHEMA)
        self.assertEqual(plan["peers"], [])
        self.assertFalse(plan["data_plane_enforced"])

    def test_one_way_rules_produce_two_sided_adjacency_but_one_way_intent(self):
        self.store.add_policy("users", "services", "tcp", [22, 443])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        outgoing = build_peer_plan(self.store, self.client["id"])
        incoming = build_peer_plan(self.store, self.server["id"])
        self.assertEqual(len(outgoing["peers"]), 1)
        self.assertEqual(outgoing["peers"][0]["allowed_ips"], ["10.234.12.11/32"])
        self.assertEqual(outgoing["peers"][0]["intended_egress"], [
            {"protocol": "tcp", "ports": [22, 443]}
        ])
        self.assertEqual(outgoing["peers"][0]["intended_ingress"], [])
        self.assertEqual(incoming["peers"][0]["intended_egress"], [])
        self.assertEqual(incoming["peers"][0]["intended_ingress"], [
            {"protocol": "tcp", "ports": [22, 443]}
        ])
        fragment = render_wireguard_peer_fragments(outgoing)
        self.assertIn("[Peer]", fragment)
        self.assertIn("AllowedIPs = 10.234.12.11/32", fragment)
        self.assertIn("Endpoint = 192.0.2.30:51820", fragment)
        self.assertNotIn("PrivateKey =", fragment)
        self.assertNotIn("AllowedIPs = 0.0.0.0/0", fragment)
        self.assertFalse(outgoing["wireguard_tunnels_active"])
        self.assertNotIn("private_key", json.dumps(outgoing).lower())

    def test_revocation_excludes_peer_and_does_not_reactivate(self):
        self.store.add_policy("users", "services", "icmp", [])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        self.assertEqual(len(build_peer_plan(self.store, self.client["id"])["peers"]), 1)
        self.assertTrue(self.store.revoke_peer(self.server["id"]))
        self.assertEqual(build_peer_plan(self.store, self.client["id"])["peers"], [])
        self.assertFalse(self.store.approve_peer(self.server["id"]))

    def test_renderer_refuses_duplicate_cryptokey_or_private_address_intents(self):
        self.store.add_policy("users", "services", "tcp", [443])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        original = build_peer_plan(self.store, self.client["id"])
        peer = original["peers"][0]

        plan = deepcopy(original)
        duplicate = deepcopy(peer)
        duplicate["peer_id"] = "synthetic-second-identity"
        plan["peers"].append(duplicate)
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)

        # A different public key cannot share the same AllowedIPs /32.
        plan["peers"][1]["public_key"] = key(32)
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)

        # Duplicate identity labels cannot shadow separate keys/addresses.
        plan["peers"][1]["allowed_ips"] = ["10.234.12.12/32"]
        plan["peers"][1]["peer_id"] = peer["peer_id"]
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)

    def test_renderer_refuses_forged_active_status_or_unbounded_peer_lists(self):
        self.store.add_policy("users", "services", "tcp", [443])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        original = build_peer_plan(self.store, self.client["id"])
        for field in ("wireguard_tunnels_active", "data_plane_enforced"):
            with self.subTest(field=field):
                plan = deepcopy(original)
                plan[field] = True
                with self.assertRaises(ValidationError):
                    render_wireguard_peer_fragments(plan)
                del plan[field]
                with self.assertRaises(ValidationError):
                    render_wireguard_peer_fragments(plan)
        plan = deepcopy(original)
        plan["peers"] = [deepcopy(plan["peers"][0])] * 4097
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)
        self.assertIn("[Peer]", render_wireguard_peer_fragments(original))

    def test_renderer_rejects_tampered_prefixes(self):
        self.store.add_policy("users", "services", "tcp", [443])
        self.store.approve_peer(self.client["id"])
        self.store.approve_peer(self.server["id"])
        plan = build_peer_plan(self.store, self.client["id"])
        plan["peers"][0]["allowed_ips"] = ["0.0.0.0/0"]
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)
        plan["peers"][0]["allowed_ips"] = ["127.0.0.1/32"]
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)


if __name__ == "__main__":
    unittest.main()

import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.diagnostics import evaluate_access, management_status, policy_diagnostics, simulate_access


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.temp.name) / "state.db", subnet="10.0.0.0/28")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.store.close)
        self.a = self.peer("alice", 1, ["users"])
        self.b = self.peer("server", 2, ["infra"])
        self.rule = self.store.add_policy("users", "infra", "tcp", [22, 443])

    def peer(self, name, number, groups):
        return self.store.add_peer(name, base64.b64encode(bytes([number]) * 32).decode(), groups)

    def approve(self):
        self.store.approve_peer(self.a["id"])
        self.store.approve_peer(self.b["id"])

    def explain(self, **overrides):
        args = dict(source_id=self.a["id"], target_id=self.b["id"], protocol="tcp", port=22)
        args.update(overrides)
        return self.store.explain_access(**args)

    def test_status_tracks_lifecycle_without_reusing_revoked_addresses(self):
        before = management_status(self.store)
        self.assertEqual(before["address_pool"]["capacity"], 5)
        self.assertEqual(before["address_pool"]["available"], 3)
        self.assertEqual(before["peers"]["pending"], 2)
        self.approve()
        self.store.revoke_peer(self.b["id"])
        status = management_status(self.store)
        self.assertEqual(status["peers"], {"total": 2, "approved": 1, "revoked": 1, "pending": 0})
        self.assertEqual(status["address_pool"]["allocated"], 2)
        self.assertEqual(status["address_pool"]["available"], 3)
        self.assertFalse(status["address_pool"]["revoked_addresses_reusable"])
        self.assertEqual(status["dns_record_count"], 1)
        self.assertEqual(status["groups"], [
            {"name": "infra", "approved": 0, "pending": 0, "revoked": 1},
            {"name": "users", "approved": 1, "pending": 0, "revoked": 0},
        ])
        for flag in ("wireguard_tunnels_active", "data_plane_enforced", "dns_server_running"):
            self.assertFalse(status[flag])

    def test_status_pool_exhaustion_and_configuration_mismatch(self):
        for i in range(3, 6):
            self.peer("peer" + str(i), i, [])
        self.assertEqual(management_status(self.store)["address_pool"]["available"], 0)
        with self.assertRaises(ValidationError):
            self.peer("overflow", 6, [])
        # Report old records outside the configured pool, never pretend to move them.
        with self.store.db:
            self.store.db.execute("UPDATE peers SET address='10.1.0.10' WHERE id=?", (self.a["id"],))
        pool = management_status(self.store)["address_pool"]
        self.assertEqual(pool["out_of_pool_records"], 1)
        self.assertEqual(pool["available"], 1)
        # An unreadable address is counted out of pool instead of raising.
        with self.store.db:
            self.store.db.execute("UPDATE peers SET address='not-an-address' WHERE id=?", (self.b["id"],))
        pool = management_status(self.store)["address_pool"]
        self.assertEqual(pool["out_of_pool_records"], 2)
        self.assertEqual(pool["allocated"], 3)
        self.assertEqual(pool["available"], pool["capacity"] - 3)

    def test_explanations_follow_lifecycle_and_direction(self):
        self.assertEqual(self.explain()["reason"], "peer_not_approved")
        self.approve()
        decision = self.explain()
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["matching_policy_ids"], [self.rule["id"]])
        self.assertEqual(decision["reason"], "matching_allow_policy")
        self.assertFalse(decision["data_plane_enforced"])
        self.assertEqual(self.explain(port=80)["reason"], "default_deny")
        self.assertEqual(self.explain(protocol="udp")["reason"], "default_deny")
        self.assertEqual(self.explain(source_id=self.b["id"], target_id=self.a["id"])["reason"], "default_deny")
        self.assertEqual(self.explain(target_id=self.a["id"])["reason"], "self_access_denied")
        self.assertEqual(self.explain(target_id="missing")["reason"], "peer_not_found")
        self.store.revoke_peer(self.b["id"])
        self.assertEqual(self.explain()["reason"], "peer_not_approved")

    def test_all_matching_policies_and_icmp(self):
        self.approve()
        duplicate = self.store.add_policy("users", "infra", "tcp", [22])
        self.assertEqual(self.explain()["matching_policy_ids"], sorted([self.rule["id"], duplicate["id"]]))
        icmp = self.store.add_policy("users", "infra", "icmp", [])
        self.assertEqual(self.explain(protocol="icmp", port=None)["matching_policy_ids"], [icmp["id"]])
        for overrides in ({"port": True}, {"port": 0}, {"port": 65536}, {"port": "22"},
                          {"protocol": "icmp"}, {"protocol": "all"}, {"source_id": None}):
            with self.subTest(overrides=overrides), self.assertRaises(ValidationError):
                self.explain(**overrides)

    def test_duplicate_peer_id_fails_closed_in_access_explanation(self):
        self.approve()
        peers, policies = self.store.snapshot()
        duplicate = dict(peers[1])
        duplicate["id"] = peers[0]["id"]
        duplicate["groups"] = ["infra"]
        for rows in (peers + [duplicate], [duplicate] + peers):
            with self.assertRaisesRegex(ValidationError, "duplicate peer identity"):
                evaluate_access(rows, policies, self.a["id"], self.b["id"], "tcp", 22)

    def test_batch_matches_single_evaluator_and_does_not_mutate(self):
        self.approve()
        checks = [{"source_id": self.a["id"], "target_id": self.b["id"], "protocol": "tcp", "port": p}
                  for p in (22, 80, 443)]
        before = (self.store.snapshot(), self.store.events())
        result = simulate_access(self.store, checks)
        self.assertEqual([r["allowed"] for r in result["results"]], [True, False, True])
        for check, decision in zip(checks, result["results"]):
            self.assertEqual(decision, self.store.explain_access(**check))
            self.assertEqual(decision["allowed"], self.store.allowed(**check))
        self.assertEqual(before, (self.store.snapshot(), self.store.events()))
        self.assertEqual(len(simulate_access(self.store, checks[:1] * 100)["results"]), 100)

    def test_access_simulation_uses_bounded_reader_when_available(self):
        self.approve()
        peers, policies = self.store.snapshot()

        class BoundedFixture:
            def snapshot(self):
                raise AssertionError("unbounded snapshot must not be used")

            def snapshot_bounded(self, *, max_peers, max_policies):
                self.limits = (max_peers, max_policies)
                return peers, policies

        fixture = BoundedFixture()
        checks = [{"source_id": self.a["id"], "target_id": self.b["id"],
                   "protocol": "tcp", "port": 22}]
        self.assertTrue(simulate_access(fixture, checks)["results"][0]["allowed"])
        self.assertEqual(fixture.limits, (4096, 4096))

    def test_access_simulation_rejects_oversized_fallback_snapshot(self):
        class UnboundedFixture:
            def snapshot(self):
                return [{"id": str(i)} for i in range(4097)], []

        checks = [{"source_id": "a", "target_id": "b",
                   "protocol": "icmp"}]
        with self.assertRaisesRegex(ValidationError, "bounded input limits"):
            simulate_access(UnboundedFixture(), checks)

    def test_batch_rejects_invalid_shapes_and_partial_invalid_batches(self):
        good = {"source_id": self.a["id"], "target_id": self.b["id"], "protocol": "icmp"}
        for checks in (None, {}, [], [good] * 101, [None], [good, {}], [{**good, "extra": True}],
                       [{**good, "port": 0}]):
            with self.subTest(checks=checks), self.assertRaises(ValidationError):
                simulate_access(self.store, checks)

    def test_policy_diagnostics_duplicates_and_approved_members_only(self):
        duplicate = self.store.add_policy("users", "infra", "tcp", [443, 22, 22])
        overlap = self.store.add_policy("users", "infra", "tcp", [22])
        before = policy_diagnostics(self.store)
        self.assertEqual(before["duplicate_policy_sets"], [sorted([self.rule["id"], duplicate["id"]])])
        self.assertTrue(all(p["eligible_peer_pairs"] == 0 for p in before["policies"]))
        self.approve()
        after = policy_diagnostics(self.store)
        self.assertTrue(all(p["eligible_peer_pairs"] == 1 and p["warnings"] == [] for p in after["policies"]))
        self.assertNotIn(overlap["id"], after["duplicate_policy_sets"][0])
        self.store.revoke_peer(self.b["id"])
        self.assertTrue(all(p["warnings"] == ["no_approved_target_members"]
                            for p in policy_diagnostics(self.store)["policies"]))

    def test_group_pair_counts_exclude_self_pairs(self):
        self.store.add_policy("users", "users", "icmp", [])
        self.approve()
        rows = policy_diagnostics(self.store)["policies"]
        self.assertEqual(rows[-1]["warnings"], ["no_distinct_peer_pairs"])
        third = self.peer("bob", 3, ["users"])
        self.store.approve_peer(third["id"])
        self.assertEqual(policy_diagnostics(self.store)["policies"][-1]["eligible_peer_pairs"], 2)

    def test_event_pages_survive_new_events_without_duplicate_rows(self):
        self.approve()
        first = self.store.event_page(limit=2)
        self.assertIsNotNone(first["next_before"])
        self.store.revoke_peer(self.b["id"])
        second = self.store.event_page(limit=2, before=first["next_before"])
        seqs = [e["seq"] for e in first["events"] + second["events"]]
        self.assertEqual(len(set(seqs)), 4)
        self.assertEqual(seqs, sorted(seqs, reverse=True))
        self.assertIsNone(second["next_before"])
        filtered = self.store.event_page(peer_id=self.b["id"], kind="peer_revoked")
        self.assertEqual(len(filtered["events"]), 1)
        self.assertFalse(filtered["tamper_proof"])
        self.assertEqual(self.store.event_page(before=1)["events"], [])
        self.assertEqual(self.store.events(), self.store.event_page()["events"])

    def test_event_filters_validate_and_bind_values(self):
        for kwargs in ({"limit": True}, {"limit": 0}, {"limit": 201}, {"before": 0},
                       {"before": 2**63}, {"before": "1"}, {"kind": "unknown"},
                       {"peer_id": []}, {"peer_id": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.store.event_page(**kwargs)
        self.assertEqual(self.store.event_page(peer_id="' OR 1=1 --")["events"], [])

    def test_event_pages_can_read_beyond_legacy_200_limit(self):
        with self.store.lock, self.store.db:
            for _ in range(205):
                self.store._event("peer_registered", self.a["id"])
        first = self.store.event_page()
        second = self.store.event_page(before=first["next_before"])
        self.assertEqual(len(first["events"]), 200)
        self.assertEqual(len(second["events"]), 7)
        self.assertIsNone(second["next_before"])

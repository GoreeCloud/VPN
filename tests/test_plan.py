"""Offline peer planning tests; no network capabilities required."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

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

    def approve(self, peer):
        # Internal store-only fixture; HTTP tests verify actual key possession.
        self.assertTrue(self.store.record_device_proof(peer["id"], peer["public_key"]))
        self.assertTrue(self.store.approve_peer(peer["id"]))

    def test_unapproved_local_peer_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_peer_plan(self.store, self.client["id"])

    def test_default_deny_excludes_unrelated_peers(self):
        self.approve(self.client)
        self.approve(self.server)
        plan = build_peer_plan(self.store, self.client["id"])
        self.assertEqual(plan["schema"], PLAN_SCHEMA)
        self.assertEqual(plan["peers"], [])
        self.assertFalse(plan["data_plane_enforced"])

    def test_one_way_rules_produce_two_sided_adjacency_but_one_way_intent(self):
        self.store.add_policy("users", "services", "tcp", [22, 443])
        self.approve(self.client)
        self.approve(self.server)
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
        self.approve(self.client)
        self.approve(self.server)
        self.assertEqual(len(build_peer_plan(self.store, self.client["id"])["peers"]), 1)
        self.assertTrue(self.store.revoke_peer(self.server["id"]))
        self.assertEqual(build_peer_plan(self.store, self.client["id"])["peers"], [])
        self.assertFalse(self.store.approve_peer(self.server["id"]))

    def test_renderer_rejects_tampered_prefixes(self):
        self.store.add_policy("users", "services", "tcp", [443])
        self.approve(self.client)
        self.approve(self.server)
        plan = build_peer_plan(self.store, self.client["id"])
        plan["peers"][0]["allowed_ips"] = ["0.0.0.0/0"]
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)
        plan["peers"][0]["allowed_ips"] = ["127.0.0.1/32"]
        with self.assertRaises(ValidationError):
            render_wireguard_peer_fragments(plan)


if __name__ == "__main__":
    unittest.main()

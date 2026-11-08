"""Offline nftables preview never applies firewall, routes or network state."""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.firewall_preview import build_nft_ingress_preview, SCHEMA


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode("ascii")


class FirewallPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.tmp.name) / "state.db", subnet="10.77.0.0/24")
        self.sender = self.store.add_peer("sender", key(80), ["users"])
        self.server = self.store.add_peer("server", key(81), ["services"])
        self.outsider = self.store.add_peer("outsider", key(82), ["guest"])

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def approve(self, peer):
        self.assertTrue(self.store.approve_peer(peer["id"]))

    def test_pending_target_rejected_even_with_policy(self):
        self.store.add_policy("users", "services", "tcp", [443])
        with self.assertRaises(ValidationError):
            build_nft_ingress_preview(self.store, self.server["id"])

    def test_no_policy_includes_final_drop_and_no_accept(self):
        self.approve(self.sender)
        self.approve(self.server)
        plan = build_nft_ingress_preview(self.store, self.server["id"], interface="wgB")
        self.assertEqual(plan["schema"], SCHEMA)
        self.assertFalse(plan["data_plane_enforced"])
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["allow_rule_count"], 0)
        self.assertIn('iifname "wgB" ip daddr 10.77.0.11 drop', plan["nftables_text"])
        self.assertNotIn(" accept\n", plan["nftables_text"])

    def test_directional_group_protocol_and_ports(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.approve(self.outsider)
        self.store.add_policy("users", "services", "tcp", [443, 22, 443])
        self.store.add_policy("users", "services", "udp", [53])
        self.store.add_policy("users", "services", "icmp", [])
        plan = build_nft_ingress_preview(self.store, self.server["id"], interface="wgB")
        lines = plan["nftables_text"].splitlines()
        self.assertEqual(plan["allow_rule_count"], 3)
        self.assertTrue(any('ip saddr 10.77.0.10 ' in x and 'tcp dport { 22, 443 } accept' in x for x in lines))
        self.assertTrue(any('ip saddr 10.77.0.10 ' in x and 'udp dport 53 accept' in x for x in lines))
        self.assertTrue(any('ip saddr 10.77.0.10 ' in x and 'ip protocol icmp accept' in x for x in lines))
        self.assertFalse(any('ip saddr 10.77.0.12 ' in x for x in lines))
        self.assertTrue(lines[-2].endswith("}"))
        self.assertTrue(self.store.allowed(self.sender["id"], self.server["id"], "tcp", 22))
        self.assertFalse(self.store.allowed(self.server["id"], self.sender["id"], "tcp", 22))

    def test_revoked_source_excluded(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.store.add_policy("users", "services", "icmp", [])
        self.assertEqual(
            build_nft_ingress_preview(self.store, self.server["id"])["allow_rule_count"], 1
        )
        self.assertTrue(self.store.revoke_peer(self.sender["id"]))
        self.assertEqual(
            build_nft_ingress_preview(self.store, self.server["id"])["allow_rule_count"], 0
        )

    def test_input_interface_is_validated_and_no_injection(self):
        self.approve(self.server)
        for interface in ("", "0wg", "wg0;drop", 'wg"0', "x" * 16, "wg 0"):
            with self.subTest(interface=interface), self.assertRaises(ValidationError):
                build_nft_ingress_preview(self.store, self.server["id"], interface=interface)

    def test_private_pool_address_fails_closed_when_corrupted(self):
        self.approve(self.sender)
        self.approve(self.server)
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "UPDATE peers SET address='8.8.8.8' WHERE id=?", (self.sender["id"],)
            )
        with self.assertRaises(ValidationError):
            build_nft_ingress_preview(self.store, self.server["id"])

    def test_reserved_network_and_broadcast_addresses_are_rejected(self):
        self.approve(self.sender)
        self.approve(self.server)
        for address in ("10.77.0.0", "10.77.0.255"):
            with self.subTest(address=address):
                with self.store.lock, self.store.db:
                    self.store.db.execute(
                        "UPDATE peers SET address=? WHERE id=?",
                        (address, self.sender["id"]),
                    )
                with self.assertRaises(ValidationError):
                    build_nft_ingress_preview(self.store, self.server["id"])

    def test_stored_policy_rejects_invalid_protocol_value(self):
        self.approve(self.sender)
        self.approve(self.server)
        rule = self.store.add_policy("users", "services", "icmp", [])
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "UPDATE policies SET protocol='[1,2]' WHERE id=?", (rule["id"],)
            )
        with self.assertRaises(ValidationError):
            build_nft_ingress_preview(self.store, self.server["id"])

    def test_duplicate_rules_are_stable_and_snapshot_not_mutated(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.store.add_policy("users", "services", "tcp", [443])
        self.store.add_policy("users", "services", "tcp", [443])
        before = self.store.snapshot()
        p1 = build_nft_ingress_preview(self.store, self.server["id"])
        p2 = build_nft_ingress_preview(self.store, self.server["id"])
        self.assertEqual(p1, p2)
        self.assertEqual(p1["allow_rule_count"], 1)
        self.assertEqual(self.store.snapshot(), before)


if __name__ == "__main__":
    unittest.main()

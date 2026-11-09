"""Offline nftables preview never applies firewall, routes or network state."""
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from proven_peer_fixture import key, prove_and_approve
from goreecloud_vpn.firewall_preview import build_nft_ingress_preview, SCHEMA




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
        self.assertTrue(prove_and_approve(self.store, peer))

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
        self.assertIn('iifname "wgB" drop', plan["nftables_text"])
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

    def test_reverse_group_direction_is_default_deny(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.store.add_policy("users", "services", "icmp", [])
        forward = build_nft_ingress_preview(self.store, self.server["id"], interface="wgB")
        reverse = build_nft_ingress_preview(self.store, self.sender["id"], interface="wgA")
        self.assertEqual(forward["allow_rule_count"], 1)
        self.assertEqual(reverse["allow_rule_count"], 0)
        self.assertIn('iifname "wgA" drop', reverse["nftables_text"])
        self.assertNotIn('ip saddr 10.77.0.11 ', reverse["nftables_text"])
        self.assertFalse(reverse["applied"])

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

    def test_replacement_transaction_is_explicitly_offline_and_fail_closed(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.store.add_policy("users", "services", "tcp", [443])
        plan = build_nft_ingress_preview(self.store, self.server["id"], interface="wgB")
        text = plan["nftables_replace_transaction_text"]
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(lines[0], "flush chain inet goreecloud_vpn_preview input")
        self.assertEqual(len(lines), 3)
        self.assertIn('ip saddr 10.77.0.10 ip daddr 10.77.0.11 tcp dport 443 accept', lines[1])
        self.assertTrue(lines[-1].endswith('iifname "wgB" drop'))
        self.assertNotIn('delete table', text)
        self.assertNotIn('flush ruleset', text)
        self.assertTrue(plan["existing_table_required_for_replacement"])
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["data_plane_enforced"])

    def test_terminal_drop_is_interface_wide_and_not_target_ip_scoped(self):
        self.approve(self.sender)
        self.approve(self.server)
        self.store.add_policy("users", "services", "tcp", [443])
        plan = build_nft_ingress_preview(self.store, self.server["id"], interface="wgB")
        nft_lines = plan["nftables_text"].splitlines()
        txn_lines = plan["nftables_replace_transaction_text"].splitlines()
        self.assertEqual(nft_lines[-3].strip(), 'iifname "wgB" drop')
        self.assertEqual(txn_lines[-1], 'add rule inet goreecloud_vpn_preview input iifname "wgB" drop')
        self.assertEqual(plan["allow_rule_count"], 1)
        self.assertNotIn('iifname "wgB" ip daddr 10.77.0.11 drop', plan["nftables_text"])
        self.assertFalse(plan["applied"])

    def test_default_deny_transaction_keeps_terminal_drop(self):
        self.approve(self.server)
        plan = build_nft_ingress_preview(self.store, self.server["id"])
        lines = [line for line in plan["nftables_replace_transaction_text"].splitlines()
                 if not line.startswith("#")]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "flush chain inet goreecloud_vpn_preview input")
        self.assertTrue(lines[1].endswith('iifname "wg0" drop'))

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

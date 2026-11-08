"""Untrusted WireGuard public AllowedIPs text inspection regressions."""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.identity_binding import build_key_address_binding_intent
from goreecloud_vpn.kernel_readback import (
    SCHEMA, compare_allowedips_to_intent, parse_allowedips_text,
)


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class KernelAllowedIPsReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.temp.name) / "state.db", subnet="10.77.0.0/24")
        self.source = self.store.add_peer("source", key(100), ["users"])
        self.target = self.store.add_peer("target", key(101), ["services"])
        self.assertTrue(self.store.approve_peer(self.source["id"]))
        self.assertTrue(self.store.approve_peer(self.target["id"]))
        self.intent = build_key_address_binding_intent(self.store)
        self.selected = [self.source["id"]]
        self.good_text = key(100) + "\t10.77.0.10/32\n"

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def compare(self, output):
        return compare_allowedips_to_intent(
            self.intent, output, expected_peer_ids=self.selected
        )

    def test_exact_public_readback_matches_without_claiming_authentication(self):
        comparison = self.compare(self.good_text)
        self.assertEqual(comparison["schema"], SCHEMA)
        self.assertTrue(comparison["text_matches_selected_intent"])
        self.assertEqual(comparison["expected_count"], 1)
        self.assertEqual(comparison["observed_count"], 1)
        self.assertFalse(comparison["readback_source_authenticated"])
        self.assertFalse(comparison["active_kernel_state_attested"])
        self.assertFalse(comparison["applied"])
        self.assertFalse(comparison["data_plane_enforced"])

    def test_missing_or_unexpected_peers_fail_closed(self):
        missing = self.compare("")
        self.assertFalse(missing["text_matches_selected_intent"])
        self.assertEqual(missing["missing_public_keys"], [key(100)])
        unexpected = self.compare(self.good_text + key(101) + "\t10.77.0.11/32\n")
        self.assertFalse(unexpected["text_matches_selected_intent"])
        self.assertEqual(unexpected["unexpected_public_keys"], [key(101)])

    def test_correct_key_wrong_address_is_not_accepted(self):
        mismatched = self.compare(key(100) + "\t10.77.0.12/32\n")
        self.assertFalse(mismatched["text_matches_selected_intent"])
        self.assertEqual(mismatched["mismatched_public_keys"], [key(100)])

    def test_malformed_multiple_prefixes_and_mixed_cases_rejected(self):
        invalid = [
            key(100) + " 10.77.0.10/32\n",
            key(100) + "\t0.0.0.0/0\n",
            key(100) + "\t10.77.0.10/24\n",
            key(100) + "\t10.77.0.0/32\n",
            key(100) + "\t10.77.0.255/32\n",
            key(100) + "\t127.0.0.1/32\n",
            key(100) + "\t10.77.0.10/32, 10.77.0.11/32\n",
            key(100) + "\t(none)\n",
            "bad-key\t10.77.0.10/32\n",
            key(100) + "\t10.77.0.10/32\tunexpected\n",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.compare(value)

    def test_duplicate_key_or_ip_rejected(self):
        for value in (
            self.good_text + self.good_text,
            self.good_text + key(101) + "\t10.77.0.10/32\n",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                parse_allowedips_text(value, pool="10.77.0.0/24")

    def test_unapproved_or_unknown_selection_rejected(self):
        self.assertTrue(self.store.revoke_peer(self.target["id"]))
        intent = build_key_address_binding_intent(self.store)
        with self.assertRaises(ValidationError):
            compare_allowedips_to_intent(
                intent, self.good_text, expected_peer_ids=[self.target["id"]]
            )
        for peer_ids in ([self.source["id"], self.source["id"]], ["unknown"]):
            with self.subTest(peer_ids=peer_ids), self.assertRaises(ValidationError):
                compare_allowedips_to_intent(
                    self.intent, self.good_text, expected_peer_ids=peer_ids
                )

    def test_invalid_manifest_and_oversized_output_fail_closed(self):
        bad = dict(self.intent)
        bad["schema"] = "other"
        with self.assertRaises(ValidationError):
            compare_allowedips_to_intent(bad, self.good_text, expected_peer_ids=self.selected)
        with self.assertRaises(ValidationError):
            parse_allowedips_text("X" * 262145, pool="10.77.0.0/24")

    def test_invalid_declared_count_and_invalid_unicode_fail_closed(self):
        malformed = dict(self.intent)
        malformed["binding_count"] = 0
        with self.assertRaises(ValidationError):
            compare_allowedips_to_intent(
                malformed, self.good_text, expected_peer_ids=self.selected
            )
        with self.assertRaises(ValidationError):
            parse_allowedips_text("\ud800", pool="10.77.0.0/24")

    def test_different_key_cannot_impersonate_selected_peer(self):
        comparison = self.compare(key(101) + "\t10.77.0.10/32\n")
        self.assertFalse(comparison["text_matches_selected_intent"])
        self.assertEqual(comparison["missing_public_keys"], [key(100)])
        self.assertEqual(comparison["unexpected_public_keys"], [key(101)])


if __name__ == "__main__":
    unittest.main()

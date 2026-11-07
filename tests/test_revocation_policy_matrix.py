"""Management-only regression: revocation denies both directions for all protocols.

This test does not create WireGuard interfaces or assert packet enforcement.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore


def public_key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class RevocationPolicyMatrixTests(unittest.TestCase):
    def test_revocation_invalidates_existing_bidirectional_allows(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                left = store.add_peer("left", public_key(71), ["leftgroup"])
                right = store.add_peer("right", public_key(72), ["rightgroup"])
                self.assertTrue(store.approve_peer(left["id"]))
                self.assertTrue(store.approve_peer(right["id"]))
                for source, target in (("leftgroup", "rightgroup"),
                                       ("rightgroup", "leftgroup")):
                    store.add_policy(source, target, "tcp", [443])
                    store.add_policy(source, target, "udp", [53])
                    store.add_policy(source, target, "icmp", [])

                checks = (("tcp", 443), ("udp", 53), ("icmp", None))
                directions = ((left["id"], right["id"]),
                              (right["id"], left["id"]))
                for source, target in directions:
                    for protocol, port in checks:
                        with self.subTest(phase="approved", source=source,
                                          protocol=protocol):
                            decision = store.explain_access(source, target, protocol, port)
                            self.assertTrue(decision["allowed"])
                            self.assertEqual(decision["reason"], "matching_allow_policy")
                            self.assertFalse(decision["data_plane_enforced"])

                self.assertTrue(store.revoke_peer(right["id"]))
                for source, target in directions:
                    for protocol, port in checks:
                        with self.subTest(phase="revoked", source=source,
                                          protocol=protocol):
                            decision = store.explain_access(source, target, protocol, port)
                            self.assertFalse(decision["allowed"])
                            self.assertEqual(decision["reason"], "peer_not_approved")
                            self.assertEqual(decision["matching_policy_ids"], [])
                            self.assertFalse(decision["data_plane_enforced"])
                self.assertFalse(store.approve_peer(right["id"]))
            finally:
                store.close()


    def test_policy_deletion_denies_both_directions_without_revoking_peers(self):
        """Management-only regression: deleting an allow rule must fail closed."""
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                left = store.add_peer("left", public_key(81), ["leftgroup"])
                right = store.add_peer("right", public_key(82), ["rightgroup"])
                self.assertTrue(store.approve_peer(left["id"]))
                self.assertTrue(store.approve_peer(right["id"]))
                directions = (
                    (left["id"], right["id"], "leftgroup", "rightgroup"),
                    (right["id"], left["id"], "rightgroup", "leftgroup"),
                )
                rules = []
                for _, _, source_group, target_group in directions:
                    rules.append(store.add_policy(source_group, target_group, "tcp", [443]))
                for source, target, _, _ in directions:
                    decision = store.explain_access(source, target, "tcp", 443)
                    self.assertTrue(decision["allowed"])
                    self.assertFalse(decision["data_plane_enforced"])

                for rule in rules:
                    self.assertTrue(store.delete_policy(rule["id"]))
                    self.assertFalse(store.delete_policy(rule["id"]))
                for source, target, _, _ in directions:
                    with self.subTest(source=source, target=target):
                        decision = store.explain_access(source, target, "tcp", 443)
                        self.assertFalse(decision["allowed"])
                        self.assertEqual(decision["matching_policy_ids"], [])
                        self.assertFalse(decision["data_plane_enforced"])
                        # A removed permit must not affect unrelated default-deny ports.
                        self.assertFalse(store.explain_access(source, target, "tcp", 444)["allowed"])
                self.assertTrue(all(peer["status"] == "approved" for peer in store.peers()))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

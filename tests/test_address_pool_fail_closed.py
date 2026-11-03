"""Fail-closed management address allocation tests (no VPN interfaces created)."""

import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def public_key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class AddressPoolSafetyTests(unittest.TestCase):
    def test_exhaustion_and_revocation_do_not_recycle_identity_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "vpn.db"
            store = VPNStore(database, subnet="10.88.0.0/28")
            try:
                # The allocator reserves the first ten addresses and the last
                # address of the subnet; a /28 therefore has five slots.
                peers = [
                    store.add_peer(f"peer{i}", public_key(i + 1), ["devices"])
                    for i in range(5)
                ]
                addresses = [peer["address"] for peer in peers]
                self.assertEqual(addresses, [
                    "10.88.0.10", "10.88.0.11", "10.88.0.12",
                    "10.88.0.13", "10.88.0.14",
                ])
                self.assertTrue(store.approve_peer(peers[0]["id"]))
                self.assertTrue(store.revoke_peer(peers[0]["id"]))
                before_events = len(store.events())
                with self.assertRaisesRegex(ValidationError, "address pool exhausted"):
                    store.add_peer("overflow", public_key(9), ["devices"])
                self.assertEqual(len(store.peers()), 5)
                self.assertEqual(len(store.events()), before_events)
            finally:
                store.close()

            # A restart must not free revoked addresses or silently enroll
            # a previously rejected peer.
            store = VPNStore(database, subnet="10.88.0.0/28")
            try:
                self.assertEqual(
                    {peer["address"] for peer in store.peers()}, set(addresses)
                )
                self.assertEqual(
                    next(peer for peer in store.peers() if peer["id"] == peers[0]["id"])["status"],
                    "revoked",
                )
                with self.assertRaisesRegex(ValidationError, "address pool exhausted"):
                    store.add_peer("overflow", public_key(9), ["devices"])
                with self.assertRaises(ValidationError):
                    store.add_peer("replacement", public_key(1), ["devices"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

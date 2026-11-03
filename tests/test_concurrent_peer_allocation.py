"""Regression coverage for atomic peer enrollment under concurrent callers.

Management-plane SQLite tests only; no WireGuard tunnel or network changes.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError


def public_key(index):
    return base64.b64encode(bytes([index]) * 32).decode("ascii")


class ConcurrentEnrollmentTests(unittest.TestCase):
    def test_unique_addresses_and_events_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.db"
            store = VPNStore(path)
            try:
                def enroll(index):
                    return store.add_peer(
                        "device%02d" % index, public_key(index), ["users"]
                    )

                with ThreadPoolExecutor(max_workers=12) as executor:
                    enrolled = list(executor.map(enroll, range(1, 25)))

                self.assertEqual(len(enrolled), 24)
                self.assertEqual(len({peer["id"] for peer in enrolled}), 24)
                self.assertEqual(len({peer["address"] for peer in enrolled}), 24)
                self.assertEqual(len({peer["public_key"] for peer in enrolled}), 24)
                self.assertTrue(all(peer["status"] == "pending" for peer in enrolled))
                self.assertEqual(len(store.events()), 24)
                self.assertTrue(all(
                    event["kind"] == "peer_registered" for event in store.events()
                ))
                self.assertFalse(store.dns_records())

                before = len(store.events())
                with self.assertRaises(ValidationError):
                    store.add_peer("duplicate", public_key(1), ["users"])
                self.assertEqual(len(store.peers()), 24)
                self.assertEqual(len(store.events()), before)
            finally:
                store.close()

            reopened = VPNStore(path)
            try:
                peers = reopened.peers()
                self.assertEqual(len(peers), 24)
                self.assertEqual(len({peer["address"] for peer in peers}), 24)
                self.assertTrue(all(peer["status"] == "pending" for peer in peers))
                self.assertEqual(len(reopened.events()), 24)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()

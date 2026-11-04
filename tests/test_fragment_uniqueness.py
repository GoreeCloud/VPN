"""Offline WireGuard fragment uniqueness checks; no network access required."""
import base64
import unittest

from goreecloud_vpn.core import ValidationError
from goreecloud_vpn.plan import PLAN_SCHEMA, render_wireguard_peer_fragments


def key(value):
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


def peer(value, prefix):
    return {"public_key": key(value), "allowed_ips": [prefix], "endpoint": None}


class FragmentUniquenessTests(unittest.TestCase):
    def render(self, peers):
        return render_wireguard_peer_fragments({"schema": PLAN_SCHEMA, "peers": peers})

    def test_distinct_keys_and_host_prefixes_are_accepted(self):
        result = self.render([
            peer(1, "10.234.12.10/32"),
            peer(2, "10.234.12.11/32"),
        ])
        self.assertEqual(result.count("[Peer]"), 2)

    def test_duplicate_host_prefix_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            self.render([
                peer(1, "10.234.12.10/32"),
                peer(2, "10.234.12.10/32"),
            ])

    def test_duplicate_public_key_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            self.render([
                peer(1, "10.234.12.10/32"),
                peer(1, "10.234.12.11/32"),
            ])

    def test_nonadjacent_duplicate_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.render([
                peer(1, "10.234.12.10/32"),
                peer(2, "10.234.12.11/32"),
                peer(3, "10.234.12.10/32"),
            ])


if __name__ == "__main__":
    unittest.main()

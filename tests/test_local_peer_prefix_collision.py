"""Fail-closed offline WireGuard peer fragment checks; no network access."""
import base64
import unittest

from goreecloud_vpn.core import ValidationError
from goreecloud_vpn.plan import PLAN_SCHEMA, render_wireguard_peer_fragments


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class LocalAddressCollisionTests(unittest.TestCase):
    def plan(self, local_address="10.234.12.10", remote_address="10.234.12.11/32"):
        return {
            "schema": PLAN_SCHEMA,
            "local_address": local_address,
            "peers": [{
                "public_key": public_key(42),
                "allowed_ips": [remote_address],
                "endpoint": None,
            }],
        }

    def test_distinct_local_and_remote_addresses_render(self):
        rendered = render_wireguard_peer_fragments(self.plan())
        self.assertIn("AllowedIPs = 10.234.12.11/32", rendered)
        self.assertNotIn("PrivateKey =", rendered)

    def test_remote_prefix_cannot_claim_local_address(self):
        with self.assertRaisesRegex(ValidationError, "overlaps local"):
            render_wireguard_peer_fragments(self.plan(remote_address="10.234.12.10/32"))

    def test_malformed_local_address_fails_closed(self):
        for address in ("not-an-ip", "10.234.12.999", "10.234.12.10/32", 42):
            with self.subTest(address=address):
                with self.assertRaises(ValidationError):
                    render_wireguard_peer_fragments(self.plan(local_address=address))

    def test_legacy_plan_without_local_address_still_renders(self):
        plan = self.plan()
        del plan["local_address"]
        self.assertIn("[Peer]", render_wireguard_peer_fragments(plan))


if __name__ == "__main__":
    unittest.main()

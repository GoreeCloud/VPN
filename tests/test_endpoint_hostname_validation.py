"""Offline WireGuard endpoint validation regression tests (no networking)."""
import unittest

from goreecloud_vpn.core import ValidationError, check_endpoint


class EndpointValidationTests(unittest.TestCase):
    def test_valid_dns_ipv4_and_ipv6_endpoints(self):
        for endpoint in (
            "vpn.example.org:51820",
            "a" * 63 + ".example:1",
            "192.0.2.30:51820",
            "[2001:db8::1]:51820",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(check_endpoint(endpoint), endpoint)

    def test_malformed_hosts_fail_closed(self):
        for endpoint in (
            ".example.org:51820",
            "example..org:51820",
            "example.org.:51820",
            "-example.org:51820",
            "example-.org:51820",
            "a" * 64 + ".example:51820",
            "999.999.999.999:51820",
            "192.0.2.999:51820",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValidationError):
                    check_endpoint(endpoint)

    def test_invalid_port_and_ipv6_fail_closed(self):
        for endpoint in ("vpn.example:0", "vpn.example:65536", "[2001:db8:::1]:51820"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValidationError):
                    check_endpoint(endpoint)


if __name__ == "__main__":
    unittest.main()

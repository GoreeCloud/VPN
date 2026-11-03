"""Endpoint validation regressions: malformed hosts must not reach WireGuard plans."""
import unittest

from goreecloud_vpn.core import ValidationError, check_endpoint


class EndpointValidationTests(unittest.TestCase):
    def test_valid_dns_ipv4_and_ipv6(self):
        for endpoint in (
            "vpn.example.org:51820", "localhost:51820", "192.0.2.10:51820",
            "[2001:db8::1]:51820", "a" * 63 + ".example:1",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(check_endpoint(endpoint), endpoint)

    def test_reject_malformed_dns_and_ip_literals(self):
        for endpoint in (
            "-vpn.example:51820", "vpn-.example:51820",
            "vpn..example:51820", ".vpn.example:51820",
            "vpn.example.:51820", "bad_host:51820",
            "256.1.2.3:51820", "192.0.2.999:51820",
            "a" * 64 + ".example:51820",
            "[not-ipv6]:51820", "vpn.example:0", "vpn.example:65536",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValidationError):
                check_endpoint(endpoint)


if __name__ == "__main__":
    unittest.main()

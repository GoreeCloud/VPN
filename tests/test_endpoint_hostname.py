"""Strict peer endpoint syntax; never resolves or connects to a network endpoint."""

from pathlib import Path
import base64
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError, check_endpoint


class EndpointHostnameTests(unittest.TestCase):
    def test_legitimate_private_hostname_ipv4_and_ipv6(self):
        for endpoint in (
            "edge:51820", "server.home.internal:443", "gateway-2.example.test:65535",
            "192.0.2.12:51820", "10.0.0.1:1", "[2001:db8::1]:51820", "[::1]:51820",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(check_endpoint(endpoint), endpoint)
        self.assertIsNone(check_endpoint(None))

    def test_malformed_host_and_ambiguous_ipv4_refused(self):
        for endpoint in (
            "node..internal:51820", ".node:51820", "node.:51820",
            "-node.internal:51820", "node-.internal:51820",
            "node._service:51820", "bad_host:51820",
            "123:51820", "127.1:51820", "010.0.0.1:51820",
            "999.999.999.999:51820", "1.2.3.256:51820",
            "x" * 64 + ".example:51820",
            "node.example:00000", "node.example:65536",
            "[2001:db8:::1]:51820", "[2001:db8::1%eth0]:51820",
            "http://node.example:51820", "user@node.example:51820",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValidationError):
                check_endpoint(endpoint)

    def test_invalid_peer_endpoint_creates_no_database_record(self):
        with tempfile.TemporaryDirectory() as d:
            store = VPNStore(Path(d) / "state.db")
            try:
                before = len(store.peers())
                key = base64.b64encode(b"u" * 32).decode("ascii")
                with self.assertRaises(ValidationError):
                    store.add_peer("testnode", key, ["users"], "node..internal:51820")
                self.assertEqual(len(store.peers()), before)
                good = store.add_peer("testnode", key, ["users"], "vpn.internal:51820")
                self.assertEqual(good["endpoint"], "vpn.internal:51820")
                self.assertEqual(good["status"], "pending")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

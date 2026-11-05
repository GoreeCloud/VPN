"""Loopback IPv4/IPv6 management binding and HTTP trust-boundary regressions."""

import http.client
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.server import create_server


class ManagementLoopbackFamilyTests(unittest.TestCase):
    def test_ipv4_retains_original_socket_family(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                server = create_server(store, "x" * 48, "127.0.0.1", 0)
                try:
                    self.assertEqual(server.address_family, socket.AF_INET)
                    self.assertEqual(server.server_address[0], "127.0.0.1")
                finally:
                    server.server_close()
            finally:
                store.close()

    def test_non_loopback_ipv6_is_rejected_before_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            try:
                for host in ("::", "2001:db8::1"):
                    with self.subTest(host=host):
                        with self.assertRaises(ValidationError):
                            create_server(store, "x" * 48, host, 0)
            finally:
                store.close()

    @unittest.skipUnless(socket.has_ipv6, "IPv6 socket support unavailable")
    def test_ipv6_health_and_authenticated_route(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "vpn.db")
            server = None
            worker = None
            try:
                # Some CI systems disable IPv6 despite exposing AF_INET6.
                probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                try:
                    try:
                        probe.bind(("::1", 0))
                    except OSError as exc:
                        self.skipTest(f"IPv6 loopback unavailable: {exc}")
                finally:
                    probe.close()

                server = create_server(store, "x" * 48, "::1", 0)
                self.assertEqual(server.address_family, socket.AF_INET6)
                self.assertEqual(server.server_address[0], "::1")
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                conn = http.client.HTTPConnection("::1", server.server_port, timeout=3)
                try:
                    conn.request("GET", "/healthz")
                    health = conn.getresponse()
                    self.assertEqual(health.status, 200)
                    self.assertIn(b'"status":"ok"', health.read())
                    conn.request("GET", "/api/v1/peers")
                    protected = conn.getresponse()
                    self.assertEqual(protected.status, 401)
                    protected.read()
                finally:
                    conn.close()
            finally:
                if server is not None:
                    if worker is not None:
                        server.shutdown()
                    server.server_close()
                if worker is not None:
                    worker.join(timeout=5)
                store.close()


if __name__ == "__main__":
    unittest.main()

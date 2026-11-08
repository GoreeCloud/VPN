"""Loopback HTTP Host/Origin and request-target security regressions."""

import http.client
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from goreecloud_vpn.core import VPNStore
from goreecloud_vpn.server import create_server


class LoopbackRequestBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = VPNStore(Path(cls.temp.name) / "state.db")
        cls.token = "B" * 48
        cls.server = create_server(cls.store, cls.token, "127.0.0.1", 0)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)
        cls.store.close()
        cls.temp.cleanup()

    def request(self, target="/healthz", method="GET", *, hosts=None, origins=None,
                authorized=False):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.putrequest(method, target, skip_host=True)
        for host in (hosts if hosts is not None else [
            f"127.0.0.1:{self.server.server_port}"
        ]):
            connection.putheader("Host", host)
        for origin in origins or []:
            connection.putheader("Origin", origin)
        if authorized:
            connection.putheader("Authorization", "Bearer " + self.token)
        connection.endheaders()
        try:
            response = connection.getresponse()
            status = response.status
            response.read()
            return status
        finally:
            connection.close()

    def test_exact_literal_host_allows_health_and_admin_auth(self):
        self.assertEqual(self.request(), 200)
        self.assertEqual(self.request("/api/v1/peers"), 401)
        self.assertEqual(self.request("/api/v1/peers", authorized=True), 200)

    def test_host_spoof_and_dns_rebinding_hostname_rejected(self):
        port = self.server.server_port
        for host in (f"localhost:{port}", f"evil.example:{port}",
                     f"127.0.0.2:{port}", "127.0.0.1",
                     f"127.0.0.1:{port + 1}"):
            with self.subTest(host=host):
                self.assertEqual(self.request(hosts=[host], authorized=True), 421)

    def test_missing_duplicate_host_rejected(self):
        exact = f"127.0.0.1:{self.server.server_port}"
        self.assertEqual(self.request(hosts=[]), 421)
        self.assertEqual(self.request(hosts=[exact, exact]), 421)

    def test_all_browser_origins_rejected_even_with_valid_token(self):
        good = f"http://127.0.0.1:{self.server.server_port}"
        for origin in (good, "https://evil.example", "null"):
            with self.subTest(origin=origin):
                self.assertEqual(self.request(
                    "/api/v1/peers", origins=[origin], authorized=True
                ), 403)

    def test_absolute_form_request_target_rejected(self):
        target = f"http://127.0.0.1:{self.server.server_port}/api/v1/peers"
        self.assertEqual(self.request(target, authorized=True), 400)

    @unittest.skipUnless(socket.has_ipv6, "IPv6 not supported")
    def test_ipv6_exact_host(self):
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            try:
                probe.bind(("::1", 0))
            except OSError as exc:
                self.skipTest(f"IPv6 loopback unavailable: {exc}")
        finally:
            probe.close()
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "state.db")
            server = create_server(store, self.token, "::1", 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                connection = http.client.HTTPConnection("::1", server.server_port, timeout=3)
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                connection.close()

                connection = http.client.HTTPConnection("::1", server.server_port, timeout=3)
                connection.putrequest("GET", "/healthz", skip_host=True)
                connection.putheader("Host", f"localhost:{server.server_port}")
                connection.endheaders()
                response = connection.getresponse()
                self.assertEqual(response.status, 421)
                response.read()
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
                store.close()


if __name__ == "__main__":
    unittest.main()

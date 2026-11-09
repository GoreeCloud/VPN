"""Real ephemeral loopback HTTP resource bounds, no VPN data plane."""
import http.client
import logging
from pathlib import Path
import socket
import tempfile
import time
import threading
import unittest

from goreecloud_vpn.core import VPNStore
from goreecloud_vpn.server import (
    MAX_MANAGEMENT_CONCURRENT_CONNECTIONS, create_server,
)


class ManagementHTTPResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = VPNStore(Path(cls.temp.name) / "management.db")
        cls.token = "K" * 48
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

    def request(self, path="/healthz", fields=(), method="GET"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.putrequest(method, path, skip_host=True)
        connection.putheader("Host", f"127.0.0.1:{self.server.server_port}")
        for name, value in fields:
            connection.putheader(name, value)
        connection.endheaders()
        try:
            response = connection.getresponse()
            status = response.status
            response.read()
            return status
        finally:
            connection.close()

    def test_normal_health_and_authorized_request_still_work(self):
        self.assertEqual(self.request(), 200)
        self.assertEqual(self.request("/api/v1/peers", (
            ("Authorization", "Bearer " + self.token),
        )), 200)

    def test_excessive_header_field_count_is_431(self):
        fields = tuple((f"X-Test-{i}", "x") for i in range(64))
        self.assertEqual(self.request(fields=fields), 431)
        self.assertEqual(self.request(), 200)

    def test_large_parsed_header_metadata_is_431(self):
        self.assertEqual(self.request(fields=(("X-Filler", "x" * 8200),)), 431)
        self.assertEqual(self.request(), 200)

    def test_long_request_target_is_414(self):
        self.assertEqual(self.request("/healthz?" + "p" * 2050), 414)
        self.assertEqual(self.request(), 200)

    def test_request_path_is_redacted_from_http_logs(self):
        with self.assertLogs("goreecloud_vpn", level=logging.INFO) as captured:
            self.assertEqual(self.request("/healthz?private-secret-test=123"), 200)
        text = "\n".join(captured.output)
        self.assertNotIn("private-secret-test", text)
        self.assertNotIn("/healthz", text)

    def test_partial_header_times_out_without_responding_or_creating_state(self):
        self.server.socket_timeout_seconds = 0.15
        try:
            with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1")
                self.assertEqual(sock.recv(1024), b"")
        finally:
            self.server.socket_timeout_seconds = 5
        self.assertEqual(self.store.peers(), [])
        self.assertEqual(self.request(), 200)


class ManagementWorkerAdmissionTests(unittest.TestCase):
    """Synthetic slow clients on an owned, ephemeral 127.0.0.1 listener."""

    def test_excess_connections_are_rejected_and_capacity_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "management.db")
            server = create_server(store, "L" * 48, "127.0.0.1", 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            stalled = []
            worker.start()
            server.socket_timeout_seconds = 1.5
            try:
                for _ in range(MAX_MANAGEMENT_CONCURRENT_CONNECTIONS):
                    sock = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
                    stalled.append(sock)
                    sock.sendall(b"GET /healthz HTTP/1.1\\r\\nHost:")
                deadline = time.monotonic() + 3
                while server._worker_slots._value != 0 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(server._worker_slots._value, 0)
                with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as extra:
                    extra.settimeout(2)
                    extra.sendall(b"GET /healthz HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n\\r\\n")
                    response = extra.recv(1024)
                    self.assertIn(b"503 Service Unavailable", response)
                    self.assertIn(b"Connection: close", response)
                for sock in stalled:
                    sock.close()
                stalled.clear()
                deadline = time.monotonic() + 3
                while server._worker_slots._value != MAX_MANAGEMENT_CONCURRENT_CONNECTIONS and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(server._worker_slots._value, MAX_MANAGEMENT_CONCURRENT_CONNECTIONS)
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                try:
                    conn.request("GET", "/healthz")
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    conn.close()
            finally:
                for sock in stalled:
                    sock.close()
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
                store.close()


if __name__ == "__main__":
    unittest.main()

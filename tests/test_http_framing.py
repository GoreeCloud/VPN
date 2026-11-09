"""Real loopback HTTP regressions for ambiguous authentication and body framing.

All network connections are limited to an ephemeral local management socket.
No VPN tunnel, firewall rule, route, production database, or peer is modified.
"""
import base64
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from goreecloud_vpn.core import VPNStore
from goreecloud_vpn.server import create_server


class HTTPFramingRegressionTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.store = VPNStore(Path(self.work.name) / "state.db")
        self.token = "S" * 48
        self.server = create_server(self.store, self.token, "127.0.0.1", 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)
        self.store.close()
        self.work.cleanup()

    def request(self, method, target, fields=(), body=b""):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest(method, target, skip_host=True)
        connection.putheader("Host", f"127.0.0.1:{self.server.server_port}")
        for name, value in fields:
            connection.putheader(name, value)
        connection.endheaders(body)
        try:
            response = connection.getresponse()
            status = response.status
            response.read()
            return status
        finally:
            connection.close()

    def auth(self):
        return ("Authorization", "Bearer " + self.token)

    def test_duplicate_bearer_headers_are_denied_even_when_valid(self):
        fields = (self.auth(), self.auth())
        self.assertEqual(self.request("GET", "/api/v1/peers", fields), 401)
        self.assertEqual(self.request("GET", "/api/v1/peers", (self.auth(),)), 200)

    def test_mixed_invalid_and_valid_authorization_never_selects_one(self):
        for fields in (
            (self.auth(), ("Authorization", "Bearer rejected")),
            (("Authorization", "Bearer rejected"), self.auth()),
        ):
            with self.subTest(order=fields):
                self.assertEqual(self.request("GET", "/api/v1/peers", fields), 401)

    def test_post_requires_one_unambiguous_decimal_length(self):
        body = json.dumps({
            "source": "users", "target": "services",
            "protocol": "tcp", "ports": [443],
        }).encode("utf-8")
        baseline = (self.auth(), ("Content-Type", "application/json"))
        lengths = (
            (),
            (("Content-Length", str(len(body))), ("Content-Length", str(len(body)))),
            (("Content-Length", "1"), ("Content-Length", str(len(body)))),
            (("Content-Length", "+" + str(len(body))),),
            (("Content-Length", str(len(body)) + " "),),
            (("Content-Length", "0" * 10 + str(len(body))),),
            (("Transfer-Encoding", "chunked"), ("Content-Length", str(len(body)))),
        )
        for addition in lengths:
            with self.subTest(headers=addition):
                self.assertEqual(self.request(
                    "POST", "/api/v1/policies", baseline + addition, body
                ), 400)
        self.assertEqual(self.store.policies(), [])
        self.assertEqual(self.request(
            "POST", "/api/v1/policies", baseline + (
                ("Content-Length", str(len(body))),
                ("Content-Type", "text/plain"),
            ), body
        ), 400)
        self.assertEqual(self.store.policies(), [])
        self.assertEqual(self.request("POST", "/api/v1/policies", baseline + (
            ("Content-Length", str(len(body))),), body), 201)
        self.assertEqual(len(self.store.policies()), 1)

    def test_peer_approval_rejects_ambiguous_zero_length_without_mutating(self):
        key = base64.b64encode(bytes([79]) * 32).decode("ascii")
        peer = self.store.add_peer("test-peer", key, ["users"])
        target = f"/api/v1/peers/{peer['id']}/approve"
        for headers in (
            (("Content-Length", "0"), ("Content-Length", "0")),
            (("Content-Length", "0"), ("Content-Length", "1")),
            (("Transfer-Encoding", "chunked"),),
            (("Content-Length", "00"),),
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", target, (self.auth(),) + headers), 400)
                self.assertEqual(self.store.peers()[0]["status"], "pending")
        self.assertEqual(self.request("POST", target, (self.auth(), ("Content-Length", "0"))), 200)
        self.assertEqual(self.store.peers()[0]["status"], "approved")

    def test_health_still_remains_public_without_authentication(self):
        self.assertEqual(self.request("GET", "/healthz"), 200)


if __name__ == "__main__":
    unittest.main()

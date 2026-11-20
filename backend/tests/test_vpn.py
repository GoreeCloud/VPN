import base64
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from goreevpn.app import create_handler, HEALTH
from goreevpn.core import Conflict, InvalidInput, Store, render_server, valid_public_key

KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(range(1, 33))).decode()
TOKEN = "unit-test-token-change-in-a-real-system-123456789"


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "private" / "peers.sqlite3")

    def test_validation_and_conflicts(self):
        for bad in ("not-a-key", "a" * 44, "", "AA=="):
            with self.assertRaises(InvalidInput):
                valid_public_key(bad)
        with self.assertRaises(InvalidInput):
            self.store.enroll("../escape", KEY_A)
        peer = self.store.enroll("Laptop 1", KEY_A)
        self.assertEqual(peer["address"], "10.77.0.2/32")
        self.assertEqual(self.store.enroll("Phone", KEY_B)["address"], "10.77.0.3/32")
        with self.assertRaises(Conflict):
            self.store.enroll("Duplicate", KEY_A)
        self.assertTrue(self.store.revoke(peer["id"]))
        self.assertFalse(self.store.revoke(peer["id"]))
        with self.assertRaises(Conflict):
            self.store.enroll("Still duplicate", KEY_A)
        self.assertEqual(len(self.store.peers()), 2)

    def test_offline_config_private_and_revoked_excluded(self):
        peer = self.store.enroll("Laptop", KEY_A)
        self.store.enroll("Phone", KEY_B)
        self.store.revoke(peer["id"])
        keyfile = Path(self.tmp.name) / "server.key"
        keyfile.write_text(KEY_B + "\n")
        os.chmod(keyfile, 0o600)
        target = Path(self.tmp.name) / "wg0.conf"
        render_server(self.store, keyfile, target)
        rendered = target.read_text()
        self.assertIn("PrivateKey = " + KEY_B, rendered)
        self.assertNotIn(KEY_A, rendered)
        self.assertIn("AllowedIPs = 10.77.0.3/32", rendered)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        os.chmod(keyfile, 0o644)
        with self.assertRaises(InvalidInput):
            render_server(self.store, keyfile, target)


class HandlerTest(InventoryTest):
    def setUp(self):
        super().setUp()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), create_handler(self.store, TOKEN)
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
        h = {"Host": "localhost", **(headers or {})}
        if body is not None:
            h.setdefault("Content-Type", "application/json")
            if not isinstance(body, str):
                body = json.dumps(body)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        status, raw, hdr = r.status, r.read(), r.getheaders()
        c.close()
        return status, json.loads(raw), dict(hdr)

    def test_health_liveness_not_auth_or_data_plane(self):
        status, result, hdr = self.request("GET", "/healthz")
        self.assertEqual((status, result), (200, HEALTH))
        self.assertEqual(hdr["Cache-Control"], "no-store")
        status, _, _ = self.request("GET", "/api/v1/peers")
        self.assertEqual(status, 401)
        status, result, _ = self.request("GET", "/api/v1/readiness", headers=self.auth())
        self.assertEqual(result["data_plane"], "unverified")

    @staticmethod
    def auth():
        return {"Authorization": "Bearer " + TOKEN}

    def test_enroll_revoke_and_conflict(self):
        response = {"name": "Phone", "public_key": KEY_A}
        status, data, _ = self.request("POST", "/api/v1/peers", response, self.auth())
        self.assertEqual(status, 201)
        peer = data["peer"]
        status, data, _ = self.request("GET", "/api/v1/peers", headers=self.auth())
        self.assertEqual(len(data["peers"]), 1)
        status, _, _ = self.request("POST", "/api/v1/peers", response, self.auth())
        self.assertEqual(status, 409)
        status, _, _ = self.request("DELETE", "/api/v1/peers/" + peer["id"], headers=self.auth())
        self.assertEqual(status, 200)
        status, _, _ = self.request("DELETE", "/api/v1/peers/" + peer["id"], headers=self.auth())
        self.assertEqual(status, 404)

    def test_negative_security_cases(self):
        for headers in ({"Origin": "https://evil.example"}, {"Host": "evil.example"},
                        {"Authorization": "Bearer wrong"}):
            status, _, _ = self.request("GET", "/api/v1/peers", headers=headers)
            self.assertIn(status, (400, 401, 403))
        status, _, _ = self.request("POST", "/api/v1/peers", {"extra": 1}, self.auth())
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/v1/peers", '{"name":', self.auth())
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/v1/peers", {"name": "Phone", "public_key": KEY_A},
                                    {**self.auth(), "Content-Type": "text/plain"})
        self.assertEqual(status, 415)


if __name__ == "__main__":
    unittest.main()

import base64
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.server import create_server
from goreecloud_vpn.enrollment import device_proof
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


class ManagementHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = VPNStore(Path(cls.temp.name) / "vpn.db")
        cls.token = "a" * 48
        cls.server = create_server(cls.store, cls.token, port=0)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)
        cls.store.close()
        cls.temp.cleanup()

    def api(self, path, method="GET", data=None, authenticated=True):
        headers = {}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(self.base + path,
                      data=json.dumps(data).encode() if data is not None else None,
                      headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    @staticmethod
    def identity(seed):
        private = X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return private, base64.b64encode(public).decode("ascii")

    def prove_and_approve(self, peer_id, private):
        prefix = "/api/v1/peers/" + peer_id
        status, result = self.api(prefix + "/challenge", "POST")
        self.assertEqual(status, 201)
        challenge = result["challenge"]
        proof = device_proof(private, challenge)
        status, result = self.api(prefix + "/prove", "POST", {
            "challenge_id": challenge["challenge_id"], "proof": proof
        })
        self.assertEqual(status, 200)
        self.assertTrue(result["verified"])
        status, result = self.api(prefix + "/approve", "POST")
        self.assertEqual(status, 200)
        self.assertTrue(result["approved"])

    def test_auth_and_health(self):
        self.assertEqual(self.api("/healthz", authenticated=False)[0], 200)
        self.assertEqual(self.api("/api/v1/peers", authenticated=False)[0], 401)
        self.assertEqual(self.api("/api/v1/peers")[0], 200)

    def test_enrollment_and_policy_preview(self):
        self.assertEqual(self.api("/api/v1/peers", "POST", {"name": "missing"})[0], 400)
        key = base64.b64encode(bytes([9]) * 32).decode()
        status, data = self.api("/api/v1/peers", "POST", {
            "name": "testpeer", "public_key": key, "groups": ["users"]
        })
        self.assertEqual(status, 201)
        peer = data["peer"]
        status, result = self.api("/api/v1/access/check", "POST", {
            "source_id": peer["id"], "target_id": peer["id"],
            "protocol": "tcp", "port": 443
        })
        self.assertEqual(status, 200)
        self.assertFalse(result["allowed"])
        self.assertFalse(result["data_plane_enforced"])

    def test_admin_only_device_approval_and_revocation(self):
        private, key = self.identity(17)
        code, response = self.api("/api/v1/peers", "POST", {
            "name": "lifecycle", "public_key": key, "groups": ["users"]
        })
        self.assertEqual(code, 201)
        peer_id = response["peer"]["id"]
        self.assertEqual(response["peer"]["status"], "pending")
        path = "/api/v1/peers/" + peer_id
        self.assertEqual(self.api(path + "/approve", "POST", authenticated=False)[0], 401)
        self.assertEqual(self.api(path + "/approve", "POST")[0], 404)
        self.prove_and_approve(peer_id, private)
        code, answer = self.api(path + "/revoke", "POST")
        self.assertEqual(code, 200)
        self.assertTrue(answer["revoked"])
        self.assertFalse(answer["data_plane_enforced"])
        self.assertEqual(self.api(path + "/approve", "POST")[0], 404)
        code, answer = self.api("/api/v1/events")
        self.assertEqual(code, 200)
        self.assertFalse(answer["tamper_proof"])
        self.assertIn("peer_revoked", [row["kind"] for row in answer["events"]])

    def test_read_only_approved_peer_plan(self):
        aprivate, akey = self.identity(41)
        bprivate, bkey = self.identity(42)
        _, a = self.api("/api/v1/peers", "POST", {
            "name": "planclient", "public_key": akey, "groups": ["planusers"]
        })
        _, b = self.api("/api/v1/peers", "POST", {
            "name": "planserver", "public_key": bkey, "groups": ["planservers"]
        })
        path = "/api/v1/peers/" + a["peer"]["id"] + "/plan"
        self.assertEqual(self.api(path)[0], 404)
        self.assertEqual(self.api(path, authenticated=False)[0], 401)
        self.prove_and_approve(a["peer"]["id"], aprivate)
        self.prove_and_approve(b["peer"]["id"], bprivate)
        self.api("/api/v1/policies", "POST", {
            "source": "planusers", "target": "planservers",
            "protocol": "tcp", "ports": [443]
        })
        status, result = self.api(path)
        self.assertEqual(status, 200)
        self.assertFalse(result["plan"]["wireguard_tunnels_active"])
        self.assertFalse(result["plan"]["data_plane_enforced"])
        self.assertEqual(
            [p["peer_id"] for p in result["plan"]["peers"]],
            [b["peer"]["id"]]
        )
        self.assertEqual(result["plan"]["peers"][0]["intended_egress"], [
            {"protocol": "tcp", "ports": [443]}
        ])

    def test_guardrails(self):
        with self.assertRaises(ValidationError):
            create_server(self.store, "weak", port=0)
        with self.assertRaises(ValidationError):
            create_server(self.store, self.token, "0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()

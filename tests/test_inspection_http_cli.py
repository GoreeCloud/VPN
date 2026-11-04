import base64
from contextlib import redirect_stdout, redirect_stderr
from http.client import HTTPException
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from goreecloud_vpn import cli
from goreecloud_vpn.core import VPNStore, ValidationError
from goreecloud_vpn.server import create_server


class InspectionHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = VPNStore(Path(cls.temp.name) / "vpn.db")
        cls.token = "test-only-" + "a" * 40
        cls.server = create_server(cls.store, cls.token, port=0)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.port = cls.server.server_port
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.a = cls.store.add_peer("alice", base64.b64encode(b"a" * 32).decode(), ["users"])
        cls.b = cls.store.add_peer("server", base64.b64encode(b"b" * 32).decode(), ["infra"])
        cls.store.approve_peer(cls.a["id"])
        cls.store.approve_peer(cls.b["id"])
        cls.store.add_policy("users", "infra", "tcp", [22])
        cls.query = {"source_id": cls.a["id"], "target_id": cls.b["id"], "protocol": "tcp", "port": 22}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)
        cls.store.close()
        cls.temp.cleanup()

    def api(self, path, body=None, token=None):
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + (self.token if token is None else token)}
        req = Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urlopen(req, timeout=3)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read()), response.headers

    def test_new_routes_require_authentication(self):
        for path, body in (("/api/v1/status", None), ("/api/v1/policies/diagnostics", None),
                           ("/api/v1/events?limit=1", None), ("/api/v1/access/explain", self.query),
                           ("/api/v1/access/simulate", {"checks": [self.query]})):
            with self.subTest(path=path):
                status, result, _ = self.api(path, body, token="wrong")
                self.assertEqual(status, 401)
                self.assertEqual(result, {"error": "unauthorized"})

    def test_status_and_policy_diagnostics_are_not_live_health(self):
        code, result, headers = self.api("/api/v1/status")
        self.assertEqual(code, 200)
        self.assertEqual(result["peers"]["approved"], 2)
        self.assertFalse(result["wireguard_tunnels_active"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        code, result, _ = self.api("/api/v1/policies/diagnostics")
        self.assertEqual(code, 200)
        self.assertEqual(result["policies"][0]["eligible_peer_pairs"], 1)
        self.assertFalse(result["data_plane_enforced"])
        _, health, _ = self.api("/healthz", token="wrong")
        self.assertNotIn("peers", health)
        self.assertNotIn("address_pool", health)

    def test_access_explanation_simulation_and_backward_compatibility(self):
        code, explanation, _ = self.api("/api/v1/access/explain", self.query)
        self.assertEqual(code, 200)
        self.assertTrue(explanation["allowed"])
        self.assertEqual(explanation["reason"], "matching_allow_policy")
        code, batch, _ = self.api("/api/v1/access/simulate", {"checks": [self.query]})
        self.assertEqual(code, 200)
        self.assertEqual(batch["results"], [explanation])
        _, old, _ = self.api("/api/v1/access/check", self.query)
        self.assertEqual(old, {"allowed": True, "data_plane_enforced": False})
        for path, body in (("explain", {**self.query, "unknown": 1}),
                           ("simulate", {"checks": []}), ("simulate", {"checks": [self.query, {}]}),
                           ("simulate", {"checks": [self.query], "extra": True})):
            self.assertEqual(self.api("/api/v1/access/" + path, body)[0], 400)

    def test_event_pagination_and_invalid_filters(self):
        code, first, _ = self.api("/api/v1/events?limit=1")
        self.assertEqual(code, 200)
        self.assertEqual(len(first["events"]), 1)
        code, second, _ = self.api("/api/v1/events?limit=1&before=" + str(first["next_before"]))
        self.assertEqual(code, 200)
        self.assertLess(second["events"][0]["seq"], first["events"][0]["seq"])
        _, filtered, _ = self.api("/api/v1/events?kind=peer_approved&peer_id=" + self.a["id"])
        self.assertEqual(len(filtered["events"]), 1)
        for query in ("limit=0", "limit=201", "limit=x", "limit=", "before=-1", "before=9223372036854775808",
                      "limit=1&limit=2", "kind=wrong", "peer_id=", "typo=1", "limit=1&before=2&kind=x&peer_id=x&extra=1"):
            with self.subTest(query=query):
                self.assertEqual(self.api("/api/v1/events?" + query)[0], 400)

    def run_cli(self, args, stdin="", token=None):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GOREECLOUD_VPN_ADMIN_TOKEN": self.token if token is None else token}), \
                patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--port", str(self.port), *args])
        return code, out.getvalue(), err.getvalue()

    def test_cli_reads_every_inspection_route(self):
        commands = (["status"], ["peers"], ["policies"], ["dns"], ["diagnostics"],
                    ["events", "--limit", "1", "--peer-id", self.a["id"]],
                    ["plan", self.a["id"]],
                    ["explain", self.a["id"], self.b["id"], "tcp", "--port", "22"])
        before = (self.store.snapshot(), self.store.events())
        for command in commands:
            with self.subTest(command=command):
                code, out, err = self.run_cli(command)
                self.assertEqual((code, err), (0, ""))
                self.assertIsInstance(json.loads(out), dict)
                self.assertNotIn(self.token, out)
        code, out, err = self.run_cli(["simulate"], json.dumps({"checks": [self.query]}))
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(json.loads(out)["results"][0]["allowed"])
        self.assertEqual(before, (self.store.snapshot(), self.store.events()))

    def test_cli_failures_are_nonzero_without_leaking_token(self):
        for command, stdin, token in ((["status"], "", ""), (["status"], "", "wrong" * 10),
                                      (["simulate"], "not json", None), (["simulate"], "[]", None),
                                      (["simulate"], "x" * 16385, None),
                                      (["events", "--limit", "0"], "", None)):
            with self.subTest(command=command, stdin=stdin[:10]):
                code, out, err = self.run_cli(command, stdin, token)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("Error:"))
                self.assertNotIn(self.token, err)


class ClientSafetyTests(unittest.TestCase):
    def test_remote_and_ambiguous_hosts_rejected_before_connecting(self):
        with patch.object(cli, "HTTPConnection") as connection:
            for host in ("example.com", "localhost", "10.0.0.1", "0.0.0.0", "127.1", "::1", "127.0.0.1@evil.test"):
                with self.subTest(host=host), self.assertRaises(ValidationError):
                    cli.request(host, 8176, "a" * 48, "/api/v1/status")
            connection.assert_not_called()

    def test_token_and_port_validation(self):
        with patch.object(cli, "HTTPConnection") as connection:
            for token in ("", "short", "a" * 4097, "a" * 32 + "\r\nInjected: x", "é" * 48):
                with self.assertRaises(ValidationError):
                    cli.request("127.0.0.1", 8176, token, "/api/v1/status")
            for port in (0, 65536, True):
                with self.assertRaises(ValidationError):
                    cli.request("127.0.0.1", port, "a" * 48, "/api/v1/status")
            connection.assert_not_called()

    def test_redirect_is_not_followed_and_connection_is_closed(self):
        with patch.object(cli, "HTTPConnection") as factory:
            conn = factory.return_value
            conn.getresponse.return_value.status = 302
            with self.assertRaisesRegex(ValidationError, "HTTP 302"):
                cli.request("127.0.0.1", 8176, "a" * 48, "/api/v1/status")
            factory.assert_called_once_with("127.0.0.1", 8176, timeout=5)
            conn.request.assert_called_once()
            conn.close.assert_called_once()

    def test_response_limits_and_json_errors(self):
        for data in (b"x" * (cli.MAX_RESPONSE + 1), b"not-json", b"\xff"):
            with patch.object(cli, "HTTPConnection") as factory:
                response = factory.return_value.getresponse.return_value
                response.status = 200
                response.read.return_value = data
                with self.assertRaises(ValidationError):
                    cli.request("127.0.0.1", 8176, "a" * 48, "/api/v1/status")
                factory.return_value.close.assert_called_once()

    def test_transport_failure_is_redacted(self):
        for failure in (OSError("SECRET"), HTTPException("SECRET")):
            err = io.StringIO()
            with patch.object(cli, "request", side_effect=failure), redirect_stderr(err):
                self.assertEqual(cli.main(["status"]), 1)
            self.assertNotIn("SECRET", err.getvalue())

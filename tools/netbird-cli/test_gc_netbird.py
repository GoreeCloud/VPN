"""Isolated transport, path, policy, and secret-safety contracts for gc-netbird.

Run: GC_NETBIRD_BIN=/home/ladamian/.local/bin/gc-netbird python3 -m unittest discover -s .
"""
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

FILE = Path(os.environ.get("GC_NETBIRD_BIN", Path(__file__).with_name("gc-netbird.py")))
SPEC = importlib.util.spec_from_file_location("goreecloud_netbird_cli", str(FILE))
if SPEC is None:
    from importlib.machinery import SourceFileLoader
    SPEC = importlib.util.spec_from_loader("goreecloud_netbird_cli", SourceFileLoader("goreecloud_netbird_cli", str(FILE)))
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class FakeResponse:
    status = 200

    def __init__(self, url, body):
        self.url, self.body = url, body

    def geturl(self):
        return self.url

    def read(self, limit=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeOpener:
    def __init__(self, response=None):
        self.calls = []
        self.response = response

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return FakeResponse(
            self.response if self.response is not None else request.full_url,
            b'[{"id":"peer-1","name":"test-peer","ip":"100.64.0.10"}]'
        )


class ContractTests(unittest.TestCase):
    def test_core_resource_paths(self):
        self.assertEqual(cli.resource_path("groups"), "/api/groups")
        self.assertEqual(cli.resource_path("groups", "safe_id-2"), "/api/groups/safe_id-2")
        self.assertEqual(cli.resource_path("dns-zones"), "/api/dns/zones")
        self.assertEqual(cli.resource_path("dns-nameservers"), "/api/dns/nameservers")
        self.assertEqual(cli.resource_path("events-audit"), "/api/events/audit")
        with self.assertRaises(cli.CLIError):
            cli.resource_path("unknown")
        with self.assertRaises(cli.CLIError):
            cli.resource_path("dns-settings", "id")

    def test_nested_paths_allowed(self):
        for path in (
            "/api/dns/zones/z-3/records/record-1",
            "/api/dns/zones/z-3/records",
            "/api/dns/zones/z-3",
            "/api/networks/network_3/routers/router-2",
            "/api/networks/network_3/resources/r1",
            "/api/events/audit",
        ):
            self.assertEqual(cli.valid_path(path, "GET"), path)

    def test_unsafe_paths_blocked(self):
        for path in (
            "https://evil.test/api/groups", "//evil.test", "/api/groups/../users",
            "/api/groups/%2e%2e/users", "/api/groups//users", "/api/groups?id=1",
            "/api/admin", "/debug/vars", "/api/groups/id#secret",
            "/api/groups/a.b", "/api/groups/with space",
        ):
            with self.subTest(path=path), self.assertRaises(cli.CLIError):
                cli.valid_path(path, "GET")

    def test_mutating_collections_rejected(self):
        for method, path in (
            ("DELETE", "/api/groups"), ("DELETE", "/api/dns/zones/z1/records"),
            ("DELETE", "/api/networks/n1/routers"), ("PUT", "/api/groups"),
            ("POST", "/api/peers"), ("POST", "/api/policies/id1"),
            ("POST", "/api/dns/settings"), ("POST", "/api/dns/zones/id1"),
            ("PUT", "/api/events/audit"),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(cli.CLIError):
                cli.valid_path(path, method)

    def test_post_nested_collections_allowed(self):
        for p in ("/api/dns/zones/z/records", "/api/networks/n/routers",
                  "/api/networks/n/resources", "/api/groups", "/api/policies"):
            self.assertEqual(cli.valid_path(p, "POST"), p)

    def test_policy_requires_scoped_rules(self):
        path = "/api/policies"
        invalid = [
            {}, {"name": "test"}, {"name": "", "rules": [{}]},
            {"name": "test", "rules": []},
            {"name": "test", "rules": [{"sources": [], "destinations": ["g1"]}]},
            {"name": "test", "rules": [{"sources": ["g1"], "destinations": []}]},
            {"name": "test", "rules": [{"sources": "g1", "destinations": ["g2"]}]},
        ]
        for obj in invalid:
            with self.subTest(obj=obj), self.assertRaises(cli.CLIError):
                cli.validate_payload("POST", path, obj)
        cli.validate_payload("POST", path, {"name": "limited",
            "rules": [{"sources": ["admin-id"], "destinations": ["server-id"],
                       "protocol": "tcp", "ports": ["443"], "action": "accept"}]})

    def test_group_and_dns_validation(self):
        with self.assertRaises(cli.CLIError):
            cli.validate_payload("POST", "/api/groups", {"name": ""})
        cli.validate_payload("POST", "/api/groups", {"name": "administrators", "peers": []})
        with self.assertRaises(cli.CLIError):
            cli.validate_payload("POST", "/api/dns/zones", {"name": "private"})
        cli.validate_payload("POST", "/api/dns/zones", {
            "name": "adguard", "domain": "adguard.example.test",
            "distribution_groups": ["g-admin"], "enable_search_domain": False,
        })
        with self.assertRaises(cli.CLIError):
            cli.validate_payload("POST", "/api/dns/zones/z/records",
                                 {"name": "private.test", "type": "A", "content": ""})
        cli.validate_payload("POST", "/api/dns/zones/z/records",
                             {"name": "private.test", "type": "A",
                              "content": "100.64.0.10", "ttl": 60})

    def test_private_response_output_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "response.json"
            cli.private_save(file, '{"secret":"private"}')
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            with self.assertRaises(cli.CLIError):
                cli.private_save(file, "new content")

    def test_input_json_must_be_valid_and_not_world_writable(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "policy.json"
            file.write_text('{"name":"test","rules":[]}')
            os.chmod(file, 0o600)
            obj, data = cli.load_payload(file)
            self.assertEqual(obj["name"], "test")
            self.assertIn(b'"rules":[]', data)
            os.chmod(file, 0o666)
            with self.assertRaises(cli.CLIError):
                cli.load_payload(file)
            os.chmod(file, 0o600)
            file.write_text("{")
            with self.assertRaises(cli.CLIError):
                cli.load_payload(file)

    def test_output_redaction_recursive(self):
        secret = {"name": "name", "token": "sensitive", "rules": [
            {"key": "secret", "name": "rule", "nested": {"password": "do-not-print"}}
        ]}
        value = cli.safe_tree(secret)
        text = json.dumps(value)
        self.assertNotIn("sensitive", text)
        self.assertNotIn("do-not-print", text)
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("token", cli.compact_item(secret))

    def test_mock_transport_uses_pat_and_fixed_origin(self):
        fake = FakeOpener()
        status, rows = cli.NetBirdClient(opener=fake).request("GET", "/api/peers", "test-token")
        self.assertEqual(status, 200)
        self.assertEqual(rows[0]["name"], "test-peer")
        req, timeout = fake.calls[0]
        self.assertEqual(req.get_header("Authorization"), "Token test-token")
        self.assertEqual(req.full_url, "https://netbird.goreecloud.com/api/peers")
        self.assertLessEqual(timeout, 15)

    def test_redirect_rejected(self):
        fake = FakeOpener(response="https://evil.invalid/api/peers")
        with self.assertRaises(cli.CLIError):
            cli.NetBirdClient(opener=fake).request("GET", "/api/peers", "test-token")

    def test_dry_run_never_reads_token_or_sends_network(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "group.json"
            file.write_text('{"name":"new admin group","peers":[]}')
            os.chmod(file, 0o600)
            o = io.StringIO()
            with mock.patch.object(cli, "read_pat", side_effect=AssertionError("PAT access")):
                with mock.patch.object(cli, "NetBirdClient", side_effect=AssertionError("Network call")):
                    with contextlib.redirect_stdout(o):
                        result = cli.main(["create", "groups", "--data-file", str(file), "--dry-run"])
            self.assertEqual(result, 0)
            self.assertFalse(json.loads(o.getvalue())["network_sent"])

    def test_live_write_requires_two_explicit_gates(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "group.json"
            file.write_text('{"name":"new admins"}')
            os.chmod(file, 0o600)
            for flags in ([], ["--confirm-write"], ["--confirm-network-impact"]):
                with self.subTest(flags=flags), mock.patch.object(
                        cli, "read_pat", side_effect=AssertionError("No token access permitted")):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.main(
                            ["create", "groups", "--data-file", str(file)] + flags), 2)

    def test_delete_needs_third_gate(self):
        with mock.patch.object(cli, "read_pat", side_effect=AssertionError("No PAT for deletes")):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["delete", "groups", "some-group",
                    "--confirm-write", "--confirm-network-impact"]), 2)

    def test_live_group_or_dns_placeholder_blocked_before_auth(self):
        with tempfile.TemporaryDirectory() as t:
            payload = Path(t) / "zone.json"
            payload.write_text(json.dumps({
                "name": "adguard", "domain": "adguard.example.test",
                "enabled": True, "enable_search_domain": False,
                "distribution_groups": ["REPLACE_ADMIN_GROUP_ID"]
            }))
            os.chmod(payload, 0o600)
            with mock.patch.object(cli, "read_pat", side_effect=AssertionError("Must not read token")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(["create", "dns-zones",
                        "--data-file", str(payload),
                        "--confirm-write", "--confirm-network-impact"]), 2)
            payload.write_text(json.dumps({
                "name": "adguard.example.test", "type": "A",
                "content": "100.64.0.10", "ttl": 300
            }))
            with mock.patch.object(cli, "read_pat", side_effect=AssertionError("Must not read token")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(["api", "POST", "/api/dns/zones/REPLACE_ZONE_ID/records",
                        "--data-file", str(payload),
                        "--confirm-write", "--confirm-network-impact"]), 2)

    def test_setup_key_creation_requires_private_capture(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "key.json"
            file.write_text('{"name":"one-time-server","type":"one-off"}')
            os.chmod(file, 0o600)
            with mock.patch.object(cli, "read_pat", side_effect=AssertionError("No PAT expected")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(["create", "setup-keys", "--data-file", str(file),
                        "--confirm-write", "--confirm-network-impact"]), 2)

    def test_local_read_only_vps_inventory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "data"
            root.mkdir(mode=0o700)
            file = root / "store.db"
            with sqlite3.connect(file) as db:
                db.execute("CREATE TABLE peers (id TEXT, name TEXT, ip TEXT, meta_hostname TEXT)")
                db.execute("INSERT INTO peers VALUES (?,?,?,?)",
                           ("p1", "test-peer", "100.64.0.10", "test-host"))
            with mock.patch.object(cli, "LOCAL_DB", file):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(cli.local_list("peers"), 0)
                data = json.loads(out.getvalue())
                self.assertEqual(data["items"][0]["ip"], "100.64.0.10")
                self.assertIn("read-only", data["source"])

    def test_logout_does_not_silently_revoke_or_delete(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["logout"]), 2)


if __name__ == "__main__":
    unittest.main()

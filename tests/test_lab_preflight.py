"""Regression tests for observation-only Linux WireGuard lab prerequisites."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from goreecloud_vpn.lab_preflight import (
    CAP_NET_ADMIN, SCHEMA, _effective_net_admin, inspect_lab, main,
)


class VPNLabPreflightTests(unittest.TestCase):
    def test_capability_parser_rejects_missing_or_ambiguous_status(self):
        self.assertIsNone(_effective_net_admin(None))
        self.assertIsNone(_effective_net_admin("CapEff: invalid"))
        self.assertIsNone(_effective_net_admin(""))
        self.assertIsNone(_effective_net_admin("CapEff: 00001000\nCapEff: 00001000"))
        self.assertTrue(_effective_net_admin(f"Name: python\nCapEff:\t{1 << CAP_NET_ADMIN:016x}\n"))
        self.assertFalse(_effective_net_admin("CapEff:\t0000000000000000"))

    def test_all_observed_requirements_do_not_claim_a_real_vpn(self):
        attempted = []
        def fake_lookup(name):
            attempted.append(name)
            return "/mock/" + name
        report = inspect_lab(
            platform_name="Linux", which=fake_lookup,
            proc_status=f"CapEff:\t{1 << CAP_NET_ADMIN:016x}\n",
            module_visible=True, namespace_visible=True,
        )
        self.assertEqual(attempted, ["wg", "ip", "nft", "unshare"])
        self.assertEqual(report["schema"], SCHEMA)
        self.assertTrue(report["observed_prerequisites_present"])
        self.assertFalse(report["real_wireguard_tunnel_verified"])
        self.assertFalse(report["packet_policy_enforcement_verified"])
        self.assertFalse(report["network_mutations_performed"])
        self.assertEqual({item["status"] for item in report["checks"]}, {"pass"})

    def test_missing_tool_and_capability_are_fail_closed(self):
        report = inspect_lab(
            platform_name="Linux",
            which=lambda name: None if name == "wg" else "/mock/" + name,
            proc_status="CapEff:\t0000000000000000\n",
            module_visible=False, namespace_visible=False,
        )
        status = {item["id"]: item["status"] for item in report["checks"]}
        self.assertFalse(report["observed_prerequisites_present"])
        self.assertEqual(status["tool_wg"], "blocked")
        self.assertEqual(status["cap_net_admin"], "blocked")
        self.assertEqual(status["kernel_wireguard"], "unverified")
        self.assertEqual(status["network_namespace"], "unverified")

    def test_non_linux_environment_never_reports_preflight_ready(self):
        report = inspect_lab(
            platform_name="Windows", which=lambda _: "/mock/binary",
            proc_status=f"CapEff:\t{1 << CAP_NET_ADMIN:016x}\n",
            module_visible=True, namespace_visible=True,
        )
        self.assertFalse(report["observed_prerequisites_present"])
        self.assertEqual(report["checks"][0]["status"], "blocked")

    def test_proc_read_only_fallback_handles_unavailable_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = inspect_lab(
                platform_name="Linux", which=lambda _: None,
                proc_root=root / "proc", sys_root=root / "sys",
            )
            status = {item["id"]: item["status"] for item in result["checks"]}
            self.assertEqual(status["cap_net_admin"], "unverified")
            self.assertEqual(status["kernel_wireguard"], "unverified")
            self.assertFalse(result["network_mutations_performed"])

    def test_json_and_strict_exit_codes(self):
        with patch("goreecloud_vpn.lab_preflight.inspect_lab") as probe:
            probe.return_value = {
                "schema": SCHEMA, "checks": [],
                "observed_prerequisites_present": False,
                "real_wireguard_tunnel_verified": False,
                "packet_policy_enforcement_verified": False,
                "network_mutations_performed": False,
            }
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--json", "--strict"]), 2)
            self.assertEqual(json.loads(output.getvalue())["schema"], SCHEMA)
            probe.return_value["observed_prerequisites_present"] = True
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--json", "--strict"]), 0)


if __name__ == "__main__":
    unittest.main()

"""Safety checks for the manual, non-CI WireGuard namespace integration script.

These tests deliberately stop before the script can create an interface.
"""
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tests/integration/wireguard_rootless_smoke.sh"


@unittest.skipUnless(platform.system() == "Linux", "Linux-specific Bash script")
class IsolatedLabSafetyGuardTests(unittest.TestCase):
    def run_guard(self, args, env_extra=None):
        env = os.environ.copy()
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )

    def test_default_invocation_never_executes_network_commands(self):
        result = self.run_guard([])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--run", result.stderr)

    def test_unknown_or_unapproved_policy_mode_is_rejected(self):
        for args in (["--policy-preview"], ["--run", "--unsafe-host"]):
            with self.subTest(args=args):
                result = self.run_guard(args)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_port_probe_refuses_host_network_even_with_forged_marker(self):
        probe = SCRIPT.parent / "port_probe.py"
        for env_overrides in ({}, {
            "GOREECLOUD_ISOLATED_LAB_CHILD": "1",
            "GOREECLOUD_PARENT_NETNS": "net:[1]",
            "GOREECLOUD_PARENT_MOUNTNS": "mnt:[1]",
        }):
            env = os.environ.copy()
            for key in ("GOREECLOUD_ISOLATED_LAB_CHILD", "GOREECLOUD_PARENT_NETNS",
                        "GOREECLOUD_PARENT_MOUNTNS"):
                env.pop(key, None)
            env.update(env_overrides)
            with self.subTest(markers=env_overrides):
                result = subprocess.run(
                    [sys.executable, str(probe), "check", "tcp", "8443"],
                    env=env, text=True, capture_output=True, check=False, timeout=3,
                )
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn("isolated", result.stderr)

    def test_missing_verified_wireguard_binary_rejected_before_unshare(self):
        result = self.run_guard(["--run"], {"WG_BIN": "/nonexistent/wg"})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("unavailable", result.stderr)

    def test_spoofed_child_marker_without_fresh_namespace_is_rejected(self):
        # /bin/true exists, but no parent namespace markers are provided.
        # The guard must exit before any privileged or network operation.
        result = self.run_guard(
            ["--run"],
            {"WG_BIN": "/bin/true", "GOREECLOUD_ISOLATED_LAB_CHILD": "1",
             "GOREECLOUD_PARENT_NETNS": "", "GOREECLOUD_PARENT_MOUNTNS": ""},
        )
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("fresh isolated", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Offline integration tests for fresh NetBird owner authentication bootstrap."""
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

import bcrypt

ROOT = Path(__file__).resolve().parent

class FreshNetBirdOwnerBootstrapTests(unittest.TestCase):
    def test_bcrypt_bootstrap_is_nonreusable_and_hides_plaintext(self):
        with tempfile.TemporaryDirectory(prefix="netbird-bcrypt-test-") as tmp:
            target = Path(tmp) / "fresh-instance"
            command = [
                sys.executable, str(ROOT / "bootstrap-fresh.py"),
                "--directory", str(target),
                "--domain", "vpn.example.test",
                "--owner-email", "operator@example.test",
                "--trusted-proxy-ip", "172.18.0.2",
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(list((target / "data").iterdir()), [])
            config = (target / "config.yaml").read_text()
            password = (target / "credentials/initial-admin-password").read_text().strip()
            self.assertGreaterEqual(len(password), 40)
            self.assertNotIn(password, config)
            self.assertNotIn(password, result.stdout + result.stderr)
            password_match = re.search(r'^      password: "([^"]+)"$', config, re.M)
            self.assertIsNotNone(password_match)
            saved_hash = password_match.group(1)
            self.assertTrue(saved_hash.startswith(("$2a$", "$2b$", "$2y$")))
            self.assertTrue(bcrypt.checkpw(password.encode(), saved_hash.encode()))
            for name in ("config.yaml", "dashboard.env", "credentials/initial-admin-password"):
                path = target / name
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            second = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(second.returncode, 0)
            self.assertNotIn(password, second.stdout + second.stderr)

    def test_rejects_nonprivate_reverse_proxy(self):
        with tempfile.TemporaryDirectory(prefix="netbird-proxy-test-") as tmp:
            result = subprocess.run([
                sys.executable, str(ROOT / "bootstrap-fresh.py"),
                "--directory", str(Path(tmp) / "should-not-exist"),
                "--owner-email", "operator@example.test",
                "--trusted-proxy-ip", "8.8.8.8",
            ], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(tmp) / "should-not-exist").exists())

if __name__ == "__main__":
    unittest.main()

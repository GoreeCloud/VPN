"""Offline safety tests for the non-secret NetBird VPS deployment templates."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent

class NetBirdDeploymentContracts(unittest.TestCase):
    def test_pinned_images_and_private_host_bindings(self):
        server = (ROOT / "docker-compose.yml").read_text()
        peer = (ROOT / "docker-compose.peer.yml").read_text()
        self.assertIn("netbirdio/netbird-server@sha256:", server)
        self.assertIn("netbirdio/dashboard@sha256:", server)
        self.assertIn("netbirdio/netbird@sha256:", peer)
        self.assertNotIn(":latest", server + peer)
        self.assertIn("127.0.0.1:18081:80", server)
        self.assertIn("127.0.0.1:18080:80", server)
        self.assertIn('3478:3478/udp', server)
        self.assertIn("NET_ADMIN", peer)
        self.assertIn("NB_SETUP_KEY_FILE:", peer)
        self.assertNotRegex(peer, r"(?m)^\s+NB_SETUP_KEY:\s*\S+")

    def test_caddy_does_not_expose_adguard_publicly(self):
        caddy = (ROOT / "Caddyfile.example").read_text()
        self.assertIn("@netbird remote_ip 100.64.0.0/10", caddy)
        self.assertIn("tls internal", caddy)
        self.assertIn("respond \"Not Found\" 404", caddy)
        self.assertIn("h2c://netbird-server:80", caddy)
        self.assertIn("goreecloud-temp-adguard:3000", caddy)

    def test_no_secret_or_persistent_state_is_tracked(self):
        ignored = (ROOT / ".gitignore").read_text().splitlines()
        for entry in ("config.yaml", "dashboard.env", "data/", "client-state/", "client-setup.key"):
            self.assertIn(entry, ignored)
        for name in ("config.yaml", "client-setup.key", "dashboard.env"):
            self.assertFalse((ROOT / name).exists())

    def test_fresh_install_script_exists_and_rejects_state_reuse(self):
        source = (ROOT / "bootstrap-fresh.py").read_text()
        self.assertIn('if base.exists()', source)
        self.assertIn('secrets.token_urlsafe', source)
        self.assertIn('mkdir(mode=0o700', source)
        self.assertNotIn('migration', source.lower())

    def test_interactive_secret_bootstrap(self):
        sh = (ROOT / "enroll-vps-peer.sh").read_text()
        self.assertIn('read -r -s input', sh)
        self.assertIn('[[ ! -t 0 ]]', sh)
        self.assertIn('chmod 600 client-setup.key', sh)
        self.assertNotIn('set -x', sh)

if __name__ == "__main__":
    unittest.main()

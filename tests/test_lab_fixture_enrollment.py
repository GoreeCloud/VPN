"""Genuine disposable X25519 proofs for isolated WireGuard policy fixtures.

No kernel, network namespaces, system WireGuard interfaces, or host keys used.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from integration.generate_nft_fixtures import generate


class IsolatedProofedLabFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="goreecloud-test-lab-")
        self.root = Path(self.temp.name)
        self.secrets = []
        for peer, seed in (("a", 203), ("b", 204)):
            raw = bytes([seed]) * 32
            private = X25519PrivateKey.from_private_bytes(raw)
            public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            private_b64 = base64.b64encode(raw).decode("ascii")
            self.secrets.append(private_b64)
            private_file = self.root / (peer + ".priv")
            private_file.write_text(private_b64 + "\n", encoding="ascii")
            private_file.chmod(0o600)
            public_file = self.root / (peer + ".pub")
            public_file.write_text(base64.b64encode(public).decode("ascii") + "\n",
                                   encoding="ascii")
            public_file.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def generate_in_synthetic_test(self):
        # Only the unit-test instance bypasses namespace admission to test
        # pure private-file/crypto proof logic in a disposable temp folder.
        # The actual script must always enforce its namespace guard.
        with patch("integration.generate_nft_fixtures._assert_isolated_lab") as check:
            generate(self.root)
        check.assert_called_once_with()

    def test_direct_host_invocation_is_refused_before_any_key_is_read(self):
        with self.assertRaises(RuntimeError):
            generate(self.root)
        self.assertFalse((self.root / "fixture.db").exists())
        self.assertFalse((self.root / "lab-state.json").exists())

    def test_real_proof_gates_approve_only_disposable_peer_intent(self):
        self.generate_in_synthetic_test()
        state = json.loads((self.root / "lab-state.json").read_text())
        self.assertEqual([p["status"] for p in state["peers"]],
                         ["approved", "approved"])
        self.assertEqual(len(state["policies"]), 2)
        intent = json.loads((self.root / "binding-intent.json").read_text())
        self.assertEqual(intent["binding_count"], 2)
        self.assertFalse(intent["key_possession_verified"])
        self.assertFalse(intent["active_wireguard_state_verified"])
        self.assertFalse(intent["data_plane_enforced"])
        self.assertFalse((self.root / "fixture.db").exists())
        public_only = "\n".join(
            p.read_text() for p in self.root.iterdir()
            if p.suffix in (".json", ".nft", ".txt")
        )
        for secret in self.secrets:
            self.assertNotIn(secret, public_only)
        self.assertNotIn('"private_key"', public_only)
        for name in ("lab-state.json", "ports.nft", "ports.replace.nft"):
            self.assertEqual((self.root / name).stat().st_mode & 0o077, 0)

    def test_public_private_key_mismatch_fails_before_creating_database(self):
        self.root.joinpath("b.pub").write_text(
            self.root.joinpath("a.pub").read_text(encoding="ascii"),
            encoding="ascii",
        )
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()
        self.assertFalse((self.root / "fixture.db").exists())

    def test_insecure_or_linked_private_key_is_rejected_without_blocking(self):
        a = self.root / "a.priv"
        a.chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()
        a.chmod(0o600)
        alias = self.root / "alias"
        os.link(a, alias)
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()
        alias.unlink()
        actual = self.root / "a.actual"
        a.rename(actual)
        a.symlink_to(actual)
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()
        a.unlink()
        os.mkfifo(a, 0o600)
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()

    def test_missing_malformed_and_excessively_large_private_keys_rejected(self):
        a = self.root / "a.priv"
        for payload in (b"", b"not-base64\n", b"A" * 144):
            with self.subTest(size=len(payload)):
                a.write_bytes(payload)
                a.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    self.generate_in_synthetic_test()
        a.unlink()
        with self.assertRaises(RuntimeError):
            self.generate_in_synthetic_test()

    def test_fixture_is_never_independently_allowed_to_enforce_host_policy(self):
        self.generate_in_synthetic_test()
        content = (self.root / "ports.replace.nft").read_text()
        self.assertIn("wgB", content)
        self.assertIn("10.77.0.10", content)
        self.assertIn("10.77.0.11", content)
        self.assertNotIn("exec", content.lower())
        self.assertNotIn("sudo", content.lower())


if __name__ == "__main__":
    unittest.main()

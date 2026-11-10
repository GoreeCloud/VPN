"""Owner-private disposable WireGuard lab fixture reads; never run nft or wg."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / "integration"))
from lab_policy_transaction import _read_lab_fixture  # noqa: E402


class BoundedIsolatedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make(self, name="lab-state.json", data=b'{"test":true}'):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_fixed_names_and_valid_owner_only_ascii(self):
        self.make()
        self.assertEqual(_read_lab_fixture(self.root, "lab-state.json"),
                         '{"test":true}')
        self.make("binding-source-id.txt", b"peer-synthetic-1")
        self.assertEqual(_read_lab_fixture(self.root, "binding-source-id.txt"),
                         "peer-synthetic-1")
        self.make("ports.replace.nft", b"table inet synthetic\n")
        self.assertEqual(_read_lab_fixture(self.root, "ports.replace.nft"),
                         "table inet synthetic\n")
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "../lab-state.json")

    def test_symlink_and_hardlink_fixtures_fail_closed(self):
        self.make()
        alias = self.root / "binding-source-id.txt"
        alias.symlink_to(self.root / "lab-state.json")
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "binding-source-id.txt")
        alias.unlink()
        os.link(self.root / "lab-state.json", alias)
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "lab-state.json")

    def test_public_file_or_parent_is_refused(self):
        path = self.make()
        path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "lab-state.json")
        path.chmod(0o600)
        self.root.chmod(0o755)
        try:
            with self.assertRaises(RuntimeError):
                _read_lab_fixture(self.root, "lab-state.json")
        finally:
            self.root.chmod(0o700)
        self.assertEqual(_read_lab_fixture(self.root, "lab-state.json"),
                         '{"test":true}')

    def test_symlinked_parent_and_unavailable_file_rejected(self):
        self.make()
        alias = self.root.parent / (self.root.name + "-alias")
        alias.symlink_to(self.root, target_is_directory=True)
        try:
            with self.assertRaises(RuntimeError):
                _read_lab_fixture(alias, "lab-state.json")
        finally:
            alias.unlink()
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "ports.replace.nft")

    def test_fifo_is_rejected_without_blocking(self):
        fifo = self.root / "ports.replace.nft"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "ports.replace.nft")

    def test_empty_oversized_and_non_ascii_rejected(self):
        for data in (b"", b"x" * 65537, b"\xff"):
            with self.subTest(length=len(data)):
                self.make(data=data)
                with self.assertRaises(RuntimeError):
                    _read_lab_fixture(self.root, "lab-state.json")

    def test_small_identity_and_transaction_limits(self):
        self.make("binding-source-id.txt", b"x" * 257)
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "binding-source-id.txt")
        self.make("ports.replace.nft", b"x" * 65537)
        with self.assertRaises(RuntimeError):
            _read_lab_fixture(self.root, "ports.replace.nft")

    def test_safe_reader_never_invokes_lab_commands(self):
        from unittest.mock import patch
        self.make()
        with patch("lab_policy_transaction._exec",
                   side_effect=AssertionError("kernel commands are forbidden")):
            self.assertEqual(_read_lab_fixture(self.root, "lab-state.json"),
                             '{"test":true}')


if __name__ == "__main__":
    unittest.main()

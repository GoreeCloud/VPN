"""Pure, never-applying rootless VPN lab fixture validation and ordering."""
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent / "integration"))
from lab_policy_transaction import _load_lab_bundle, apply_lab_only  # noqa: E402

GOOD = {
    "pool": "10.77.0.0/24", "target_peer_id": "synthetic-target",
    "peers": [{"id": "one"}, {"id": "two"}],
    "policies": [{"id": "a"}, {"id": "b"}],
}


class StrictLabBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name, value in (
            ("lab-state.json", json.dumps(GOOD)),
            ("binding-source-id.txt", "synthetic-source"),
            ("ports.replace.nft", "flush chain inet private input\n"),
        ):
            item = self.root / name
            item.write_text(value, encoding="ascii")
            item.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def replace(self, text):
        (self.root / "lab-state.json").write_text(text, encoding="ascii")

    def test_exact_bundle_shape_is_read_without_any_external_command(self):
        with mock.patch("lab_policy_transaction._exec",
                        side_effect=AssertionError("wg/nft subprocess prohibited")):
            state, source, transaction = _load_lab_bundle(self.root)
        self.assertEqual(state, GOOD)
        self.assertEqual(source, "synthetic-source")
        self.assertTrue(transaction.startswith("flush chain"))

    def test_duplicate_root_and_nested_fields_fail_closed(self):
        for payload in (
            json.dumps(GOOD).replace('"pool":', '"pool":"10.77.0.0/24","pool":', 1),
            json.dumps(GOOD).replace('"id": "one"', '"id":"wrong","id": "one"', 1),
        ):
            with self.subTest(kind="duplicate"), self.assertRaisesRegex(
                RuntimeError, "invalid isolated lab policy fixture"
            ):
                self.replace(payload)
                _load_lab_bundle(self.root)

    def test_nan_and_infinity_rejected_at_any_depth(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                sample = dict(GOOD)
                self.replace(json.dumps(sample).replace(
                    '"synthetic-target"', token, 1
                ))
                with self.assertRaises(RuntimeError):
                    _load_lab_bundle(self.root)

    def test_foreign_pool_unexpected_keys_and_excess_inventory_refused(self):
        variants = [
            {**GOOD, "pool": "10.0.0.0/24"},
            {**GOOD, "production_ready": True},
            {**GOOD, "peers": [{}] * 5},
            {**GOOD, "policies": [{}] * 5},
            {**GOOD, "target_peer_id": []},
            {**GOOD, "target_peer_id": ""},
        ]
        for i, variant in enumerate(variants):
            with self.subTest(i=i):
                self.replace(json.dumps(variant))
                with self.assertRaisesRegex(
                    RuntimeError, "invalid isolated lab policy fixture"
                ):
                    _load_lab_bundle(self.root)

    def test_missing_fixture_fails_before_any_subprocess(self):
        (self.root / "ports.replace.nft").unlink()
        with mock.patch("lab_policy_transaction._exec",
                        side_effect=AssertionError("subprocess prohibited")):
            with self.assertRaises(RuntimeError):
                _load_lab_bundle(self.root)

    def test_apply_path_guards_before_first_read_only_wg_command(self):
        source = inspect.getsource(apply_lab_only)
        assert source.index("state, source_id, expected = _load_lab_bundle(directory)") < (
            source.index('observed = _exec([str(wg_binary), "show"')
        )


if __name__ == "__main__":
    unittest.main()

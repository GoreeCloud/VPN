"""Strict no-extra-rule nftables JSON readback tests (no kernel access)."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

HELPER = Path(__file__).parent / "integration" / "nft_exact_readback.py"
spec = importlib.util.spec_from_file_location("nft_exact_readback_test", HELPER)
assert spec and spec.loader
readback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readback)

SOURCE = "10.77.0.10"
TARGET = "10.77.0.11"


def chain(stage="pre"):
    entries = [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"chain": {
            "family": "inet", "table": "goreecloud_vpn_preview",
            "name": "input", "handle": 1, "type": "filter",
            "hook": "input", "prio": 0, "policy": "accept",
        }},
    ]
    for number, expr in enumerate(
        readback._expected_rules(SOURCE, TARGET, stage=stage), start=5
    ):
        entries.append({"rule": {
            "family": "inet", "table": "goreecloud_vpn_preview",
            "chain": "input", "handle": number, "expr": expr,
        }})
    return {"nftables": entries}


def validate(obj, stage="pre"):
    readback.check_exact_lab_chain(
        json.dumps(obj), source=SOURCE, target=TARGET, stage=stage
    )


class ExactNftRulesetTests(unittest.TestCase):
    def test_known_good_pre_and_post_are_accepted(self):
        validate(chain("pre"))
        validate(chain("post"), "post")

    def test_emergency_deny_has_exactly_one_terminal_interface_drop(self):
        validate(chain("deny"), "deny")
        case = chain("deny")
        case["nftables"].insert(2, copy.deepcopy(chain("pre")["nftables"][2]))
        with self.assertRaises(RuntimeError):
            validate(case, "deny")

    def test_unexpected_early_accept_rule_is_rejected(self):
        sample = chain()
        candidate = copy.deepcopy(sample["nftables"][2])
        candidate["rule"]["handle"] = 20
        candidate["rule"]["expr"] = [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                       "right": "wgB"}},
            {"accept": None},
        ]
        sample["nftables"].insert(2, candidate)
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            validate(sample)

    def test_reordered_missing_or_duplicate_drop_is_rejected(self):
        sample = chain()
        for entries in (
            sample["nftables"][:-1],
            sample["nftables"] + [copy.deepcopy(sample["nftables"][-1])],
            sample["nftables"][:2] + list(reversed(sample["nftables"][2:])),
        ):
            with self.subTest(count=len(entries)), self.assertRaises(RuntimeError):
                validate({"nftables": entries})

    def test_wrong_hook_chain_policy_or_table_is_rejected(self):
        for key, bad in (
            ("hook", "forward"), ("type", "nat"),
            ("prio", -100), ("policy", "drop"),
            ("family", "ip"), ("table", "other"),
            ("name", "output"),
        ):
            case = chain()
            case["nftables"][1]["chain"][key] = bad
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                validate(case)

    def test_unexpected_match_verdict_and_source_are_rejected(self):
        sample = chain()
        for field, value in (
            ("right", "10.77.0.12"),
            ("op", "!="),
        ):
            case = copy.deepcopy(sample)
            case["nftables"][2]["rule"]["expr"][1]["match"][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(case)
        for verdict in ({"accept": None}, {"return": None}, {"jump": {"target": "other"}}):
            case = copy.deepcopy(sample)
            case["nftables"][-1]["rule"]["expr"][-1] = verdict
            with self.subTest(verdict=verdict), self.assertRaises(RuntimeError):
                validate(case)

    def test_post_rules_must_match_exact_ports_and_protocols(self):
        for item_index, expr_index, value in (
            (2, 3, 8444), (3, 3, 5354),
        ):
            case = chain("post")
            case["nftables"][item_index]["rule"]["expr"][expr_index]["match"]["right"] = value
            with self.subTest(port=value), self.assertRaises(RuntimeError):
                validate(case, "post")

    def test_malformed_giant_invalid_unicode_and_bad_chain_handle_rejected(self):
        for bad in ("{}", '{"nftables":[]}', "x"*65537, "\ud800", None):
            with self.subTest(kind=type(bad).__name__), self.assertRaises(RuntimeError):
                readback.check_exact_lab_chain(
                    bad, source=SOURCE, target=TARGET, stage="pre"
                )
        case = chain()
        case["nftables"][1]["chain"]["handle"] = "1"
        with self.assertRaises(RuntimeError):
            validate(case)

    def test_duplicate_json_object_keys_and_unknown_rule_fields_rejected(self):
        duplicated = '{"nftables":[], "nftables":[]}'
        with self.assertRaises(RuntimeError):
            readback.check_exact_lab_chain(
                duplicated, source=SOURCE, target=TARGET, stage="pre"
            )
        bad = chain()
        bad["nftables"][2]["rule"]["unexpected"] = "accept"
        with self.assertRaises(RuntimeError):
            validate(bad)

    def test_not_for_external_or_dynamic_addresses(self):
        for addr in ("8.8.8.8", "10.77.1.10", "10.77.0.11", "not-an-ip"):
            with self.subTest(addr=addr), self.assertRaises(RuntimeError):
                readback.check_exact_lab_chain(
                    json.dumps(chain()), source=addr, target=TARGET, stage="pre"
                )


if __name__ == "__main__":
    unittest.main()

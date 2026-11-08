"""Strict structural nftables JSON chain check for disposable WireGuard tests.

Pure input validation only. This is not a general nftables policy verifier,
not a production agent and never calls nft or accesses the host filesystem.
"""
from __future__ import annotations

import ipaddress
import json

CHAIN = "input"
TABLE = "goreecloud_vpn_preview"
IFACE = "wgB"
MAX_BYTES = 65536


def _match(left: dict, right: object) -> dict:
    return {"match": {"op": "==", "left": left, "right": right}}


def _interface_expr() -> dict:
    return _match({"meta": {"key": "iifname"}}, IFACE)


def _address_expr(field: str, address: str) -> dict:
    return _match({"payload": {"protocol": "ip", "field": field}}, address)


def _port_expr(protocol: str, port: int) -> dict:
    return _match({"payload": {"protocol": protocol, "field": "dport"}}, port)


def _expected_rules(source: str, target: str, *, stage: str) -> list:
    header = [
        _interface_expr(), _address_expr("saddr", source),
        _address_expr("daddr", target),
    ]
    if stage == "pre":
        allowed = [header + [
            _match({"payload": {"protocol": "ip", "field": "protocol"}}, "icmp"),
            {"accept": None},
        ]]
    elif stage == "post":
        allowed = [
            header + [_port_expr("tcp", 8443), {"accept": None}],
            header + [_port_expr("udp", 5353), {"accept": None}],
        ]
    else:
        raise ValueError("unexpected fixed lab stage")
    return allowed + [[_interface_expr(), {"drop": None}]]


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    parsed = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate JSON object key")
        parsed[key] = value
    return parsed


def check_exact_lab_chain(
    raw_json: str, *, source: str, target: str, stage: str,
) -> None:
    """Reject any extra allow, unknown verdict, reordered rule or unsafe hook."""
    try:
        if not isinstance(raw_json, str) or len(raw_json.encode("utf-8")) > MAX_BYTES:
            raise ValueError("invalid or oversized nft chain JSON")
        if (str(ipaddress.IPv4Address(source)) != source
                or str(ipaddress.IPv4Address(target)) != target
                or source != "10.77.0.10"
                or target != "10.77.0.11"):
            raise ValueError("unexpected fixed lab peer addresses")
        data = json.loads(raw_json, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(data, dict) or set(data) != {"nftables"}:
            raise ValueError("unexpected nft JSON container")
        items = data["nftables"]
        if not isinstance(items, list) or len(items) != len(_expected_rules(source, target, stage=stage)) + 2:
            raise ValueError("unexpected nft chain entry count")
        if not isinstance(items[0], dict) or set(items[0]) != {"metainfo"}:
            raise ValueError("missing nft metadata")
        if not isinstance(items[1], dict) or set(items[1]) != {"chain"}:
            raise ValueError("unexpected nft chain metadata")
        chain = items[1]["chain"]
        if not isinstance(chain, dict) or any(chain.get(k) != v for k, v in {
            "family": "inet", "table": TABLE, "name": CHAIN,
            "type": "filter", "hook": "input", "prio": 0, "policy": "accept",
        }.items()):
            raise ValueError("wrong nft table/chain/hook/priority/policy")
        if (set(chain) != {"family", "table", "name", "handle", "type",
                           "hook", "prio", "policy"}
                or type(chain.get("handle")) is not int or chain["handle"] < 0):
            raise ValueError("unexpected nft chain handle")
        expected_rules = _expected_rules(source, target, stage=stage)
        for item, expected_expr in zip(items[2:], expected_rules):
            if not isinstance(item, dict) or set(item) != {"rule"}:
                raise ValueError("unexpected nft chain object")
            rule = item["rule"]
            if not isinstance(rule, dict) or any(rule.get(k) != v for k, v in {
                "family": "inet", "table": TABLE, "chain": CHAIN,
                "expr": expected_expr,
            }.items()):
                raise ValueError("unexpected, additional, reordered or missing nft rule")
            if (set(rule) != {"family", "table", "chain", "handle", "expr"}
                    or type(rule.get("handle")) is not int or rule["handle"] < 0):
                raise ValueError("invalid rule handle")
    except (ValueError, TypeError, KeyError, UnicodeEncodeError, OverflowError) as exc:
        raise RuntimeError("untrusted kernel nft chain fails exact lab ownership check") from exc

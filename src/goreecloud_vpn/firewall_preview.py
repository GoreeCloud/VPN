"""Read-only nftables ingress policy preview; never applies network rules.

This is NOT a privileged data-plane agent. WireGuard cryptokey routing,
atomic policy replacement, conntrack revocation, output/forward hooks and
safe production rollout are separate, unimplemented release gates.
"""
from __future__ import annotations

import ipaddress
import re

from .core import RFC1918, VPNStore, ValidationError, check_group

SCHEMA = "goreecloud.vpn.nft-ingress-preview.v1"
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
_PROTOCOLS = {"tcp", "udp", "icmp"}


def _address(value: object, pool) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError) as exc:
        raise ValidationError("invalid peer IPv4 address") from exc
    if (address not in pool or address in (pool.network_address, pool.broadcast_address)
            or not any(address in private for private in RFC1918)):
        raise ValidationError("peer address lies outside the private VPN pool")
    return address


def _groups(value: object) -> set[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValidationError("invalid peer group inventory")
    return {check_group(group) for group in value}


def _policy(value: dict) -> tuple[str, str, str, tuple[int, ...]]:
    if not isinstance(value, dict):
        raise ValidationError("invalid stored policy")
    source = check_group(value.get("source"))
    target = check_group(value.get("target"))
    proto = value.get("protocol")
    if not isinstance(proto, str) or proto not in _PROTOCOLS:
        raise ValidationError("invalid policy protocol")
    ports = value.get("ports")
    if not isinstance(ports, list) or len(ports) > 64 or any(
        type(p) is not int or not 1 <= p <= 65535 for p in ports
    ):
        raise ValidationError("invalid policy ports")
    if (proto == "icmp" and ports) or (proto in ("tcp", "udp") and not ports):
        raise ValidationError("invalid policy protocol/port combination")
    return source, target, proto, tuple(sorted(set(ports)))


def build_nft_ingress_preview(
    store: VPNStore, target_peer_id: str, *, interface: str = "wg0"
) -> dict:
    """Compile a deterministic ingress-only IPv4 test plan.

    A matching source IP is not equivalent to cryptographic peer identity.
    A future real agent MUST bind WireGuard peer public keys to AllowedIPs
    and atomically apply/revoke rules before treating policy as enforced.
    """
    if not isinstance(target_peer_id, str) or not target_peer_id:
        raise ValidationError("invalid target peer id")
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
        raise ValidationError("invalid kernel interface name")

    peers, policies = store.snapshot()
    eligible = []
    for peer in peers:
        if peer["status"] != "approved":
            continue
        eligible.append({
            "id": peer["id"],
            "address": _address(peer["address"], store.network),
            "groups": _groups(peer["groups"]),
        })
    target = next((peer for peer in eligible if peer["id"] == target_peer_id), None)
    if target is None:
        raise ValidationError("target peer is not approved")
    parsed = [_policy(rule) for rule in policies]

    allow = set()
    for src in eligible:
        if src["id"] == target_peer_id:
            continue
        for rule_source, rule_target, proto, ports in parsed:
            if rule_source in src["groups"] and rule_target in target["groups"]:
                allow.add((src["address"], proto, ports))

    lines = [
        "# GoreeCloud VPN OFFLINE INGRESS PREVIEW: NOT APPLIED",
        "# Incomplete: requires verified key-to-IP binding, trusted agent and stateful policy.",
        "table inet goreecloud_vpn_preview {",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
    ]
    for src, proto, ports in sorted(allow, key=lambda x: (int(x[0]), x[1], x[2])):
        base = (
            f'    iifname "{interface}" ip saddr {src} '
            f'ip daddr {target["address"]} '
        )
        if proto == "icmp":
            statement = "ip protocol icmp accept"
        elif len(ports) == 1:
            statement = f"{proto} dport {ports[0]} accept"
        else:
            statement = f"{proto} dport {{ {', '.join(map(str, ports))} }} accept"
        lines.append(base + statement)
    # Last rule covers every non-allowed packet destined to this host through WG.
    lines.extend([
        f'    iifname "{interface}" ip daddr {target["address"]} drop',
        "  }",
        "}",
        "",
    ])
    return {
        "schema": SCHEMA,
        "target_peer_id": target_peer_id,
        "target_ipv4": str(target["address"]),
        "interface": interface,
        "allow_rule_count": len(allow),
        "nftables_text": "\n".join(lines),
        "applied": False,
        "data_plane_enforced": False,
        "scope": "Preview of IPv4 local INPUT only; no OUTPUT/FORWARD, conntrack or atomic application",
        "warning": "A preview is not protection. Never apply to host or production networking.",
    }

"""Read-only WireGuard peer intent planning.

The output is not a complete WireGuard configuration, and it does not install
routes or enforce TCP/UDP/ICMP port restrictions. Never deploy it without a
separate verified packet enforcement mechanism.
"""
from __future__ import annotations

import ipaddress

from .core import VPNStore, ValidationError, RFC1918, check_endpoint, check_key

PLAN_SCHEMA = "goreecloud.vpn.peer-plan.v1"


def build_peer_plan(store: VPNStore, local_peer_id: str) -> dict:
    """Preview approved peer adjacency and directional policy constraints.

    A valid allowed flow in either direction requires the two devices to be
    capable of handshaking; therefore adjacency is bidirectional even when
    policy flow authorization is strictly one-way. This distinction MUST be
    enforced by the future data-plane filter, not just AllowedIPs.
    """
    if not isinstance(local_peer_id, str):
        raise ValidationError("local peer id must be a string")
    peers = {p["id"]: p for p in store.peers() if p["status"] == "approved"}
    local = peers.get(local_peer_id)
    if local is None:
        raise ValidationError("local peer is absent or not approved")

    policies = store.policies()
    targets = []
    for peer in peers.values():
        if peer["id"] == local_peer_id:
            continue
        incoming, outgoing = [], []
        local_groups, remote_groups = set(local["groups"]), set(peer["groups"])
        for rule in policies:
            policy = {"protocol": rule["protocol"], "ports": rule["ports"]}
            if rule["source"] in local_groups and rule["target"] in remote_groups:
                outgoing.append(policy)
            if rule["source"] in remote_groups and rule["target"] in local_groups:
                incoming.append(policy)
        if not incoming and not outgoing:
            continue
        targets.append({
            "peer_id": peer["id"],
            "peer_name": peer["name"],
            "public_key": peer["public_key"],
            "endpoint": peer["endpoint"],
            "allowed_ips": [str(ipaddress.IPv4Address(peer["address"])) + "/32"],
            "intended_egress": outgoing,
            "intended_ingress": incoming,
        })
    targets.sort(key=lambda p: (int(ipaddress.IPv4Address(p["allowed_ips"][0].split("/")[0])), p["peer_id"]))

    return {
        "schema": PLAN_SCHEMA,
        "local_peer_id": local["id"],
        "local_address": local["address"],
        "peers": targets,
        "wireguard_tunnels_active": False,
        "data_plane_enforced": False,
        "warning": "Planning only. WireGuard peer AllowedIPs do not enforce protocol, port or direction access policies.",
    }


def render_wireguard_peer_fragments(plan: dict) -> str:
    """Create peer stanzas for offline inspection, never device activation.

    A complete interface/private-key configuration is deliberately omitted.
    """
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ValidationError("invalid peer plan schema")
    peers = plan.get("peers")
    if not isinstance(peers, list):
        raise ValidationError("invalid peer plan")
    out = [
        "# GoreeCloud VPN: OFFLINE REVIEW ONLY; NOT AN ENFORCED VPN CONFIG",
        "# Do not apply without separately verified WireGuard identity and firewall controls.",
    ]
    for peer in peers:
        if not isinstance(peer, dict) or not isinstance(peer.get("allowed_ips"), list):
            raise ValidationError("invalid peer plan entry")
        prefixes = peer["allowed_ips"]
        if len(prefixes) != 1:
            raise ValidationError("peer must have exactly one private host prefix")
        try:
            network = ipaddress.ip_network(prefixes[0], strict=True)
        except (ValueError, TypeError) as exc:
            raise ValidationError("invalid allowed IP prefix") from exc
        if network.version != 4 or network.prefixlen != 32 or not any(network.subnet_of(r) for r in RFC1918):
            raise ValidationError("only private IPv4 /32 peer prefixes are accepted")
        key = check_key(peer.get("public_key"))
        endpoint = check_endpoint(peer.get("endpoint"))
        out.extend(("", "[Peer]", "PublicKey = " + key, "AllowedIPs = " + str(network)))
        if endpoint:
            out.append("Endpoint = " + endpoint)
    return "\n".join(out) + "\n"

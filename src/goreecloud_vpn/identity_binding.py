"""Deterministic, *nonapplying* WireGuard peer-key / IPv4 binding intent.

The management database is not an authenticated source of device identity.
This module is for inspecting proposed key-to-/32 mappings only; it never
uses the wg binary, opens sockets, or manipulates host networking.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json

from .core import RFC1918, VPNStore, ValidationError, check_endpoint, check_key

BINDING_SCHEMA = "goreecloud.vpn.key-address-binding-intent.v1"


def build_key_address_binding_intent(store: VPNStore) -> dict:
    """Return deterministic approved-only key bindings, failing on bad records.

    This does not verify that the device holds the corresponding private key,
    that any WireGuard peer is installed, or that nftables rules are active.
    """
    peers, _ = store.snapshot()
    bindings = []
    addresses: set[ipaddress.IPv4Address] = set()
    public_keys: set[str] = set()
    peer_ids: set[str] = set()

    for peer in peers:
        if not isinstance(peer, dict):
            raise ValidationError("invalid peer inventory entry")
        status = peer.get("status")
        if status not in ("pending", "approved", "revoked"):
            raise ValidationError("invalid peer lifecycle state")
        if status != "approved":
            continue

        peer_id = peer.get("id")
        if not isinstance(peer_id, str) or not peer_id or len(peer_id) > 128:
            raise ValidationError("invalid peer id")
        public_key = check_key(peer.get("public_key"))
        endpoint = check_endpoint(peer.get("endpoint"))
        try:
            address = ipaddress.IPv4Address(peer.get("address"))
        except (ValueError, TypeError) as exc:
            raise ValidationError("invalid WireGuard peer address") from exc
        network = store.network
        if (address not in network or address in
                (network.network_address, network.broadcast_address)
                or not any(address in subnet for subnet in RFC1918)):
            raise ValidationError("peer IPv4 binding must be a usable RFC1918 pool address")
        if peer_id in peer_ids or public_key in public_keys or address in addresses:
            raise ValidationError("duplicate approved WireGuard identity or IPv4 binding")

        peer_ids.add(peer_id)
        public_keys.add(public_key)
        addresses.add(address)
        bindings.append({
            "peer_id": peer_id,
            "public_key": public_key,
            "allowed_ips": [f"{address}/32"],
            "endpoint": endpoint,
        })

    bindings.sort(key=lambda p: (
        int(ipaddress.IPv4Address(p["allowed_ips"][0].split("/")[0])), p["peer_id"]
    ))
    canonical = json.dumps(
        {"schema": BINDING_SCHEMA, "pool": str(store.network),
         "bindings": bindings},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "schema": BINDING_SCHEMA,
        "pool": str(store.network),
        "bindings": bindings,
        "binding_count": len(bindings),
        "snapshot_sha256": hashlib.sha256(canonical).hexdigest(),
        "snapshot_sha256_is_authenticated": False,
        "key_possession_verified": False,
        "active_wireguard_state_verified": False,
        "applied": False,
        "data_plane_enforced": False,
        "warning": (
            "An intent hash is not a signature. Verify enrollment and reconcile "
            "active kernel WireGuard AllowedIPs before applying any packet policy."
        ),
    }

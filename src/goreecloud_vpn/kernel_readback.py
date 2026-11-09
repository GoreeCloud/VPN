"""Read-only parser for public WireGuard AllowedIPs readback, never private keys.

No subprocess invocation, network access, interface configuration or policy application.
A matching text snapshot is NOT authenticated kernel attestation.
"""
from __future__ import annotations
import ipaddress
from .core import RFC1918, ValidationError, check_key
from .identity_binding import BINDING_SCHEMA

SCHEMA = "goreecloud.vpn.allowedips-text-reconciliation.v1"
MAX_PEERS = 4096


def _pool(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid binding/readback pool") from exc
    if (network.version != 4 or not any(network.subnet_of(r) for r in RFC1918)
            or not 16 <= network.num_addresses <= 65536):
        raise ValidationError("pool must be usable RFC1918 IPv4")
    return network


def _host_prefix(value, pool):
    if not isinstance(value, str):
        raise ValidationError("invalid WireGuard host prefix")
    try:
        prefix = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValidationError("invalid WireGuard host prefix") from exc
    if (prefix.version != 4 or prefix.prefixlen != 32
            or prefix.network_address not in pool
            or prefix.network_address in (pool.network_address, pool.broadcast_address)
            or not any(prefix.subnet_of(r) for r in RFC1918)
            or str(prefix) != value):
        raise ValidationError("expected canonical private IPv4 /32")
    return value


def parse_allowedips_text(output: str, *, pool: str) -> dict[str, str]:
    """Parse public output from wg show INTERFACE allowed-ips only."""
    network = _pool(pool)
    if not isinstance(output, str):
        raise ValidationError("invalid public WireGuard readback")
    try:
        encoded_len = len(output.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValidationError("invalid public WireGuard encoding") from exc
    if encoded_len > 262144:
        raise ValidationError("oversized public WireGuard readback")
    if not output:
        return {}
    lines = output.splitlines()
    if len(lines) > MAX_PEERS:
        raise ValidationError("too many WireGuard peers")
    observed = {}
    addresses = set()
    for line in lines:
        parts = line.split("\t")
        if len(parts) != 2:
            raise ValidationError("expected public key TAB one IPv4 /32")
        key = check_key(parts[0])
        address = _host_prefix(parts[1], network)
        if key in observed or address in addresses:
            raise ValidationError("duplicate kernel key or address")
        observed[key] = address
        addresses.add(address)
    return dict(sorted(observed.items()))


def compare_allowedips_to_intent(intent: dict, output: str, *, expected_peer_ids: list[str]) -> dict:
    """Compare selected approved identities to untrusted public AllowedIPs text."""
    if not isinstance(intent, dict) or intent.get("schema") != BINDING_SCHEMA:
        raise ValidationError("invalid binding intent schema")
    network = _pool(intent.get("pool"))
    entries = intent.get("bindings")
    if (not isinstance(entries, list) or len(entries) > MAX_PEERS
            or type(intent.get("binding_count")) is not int
            or intent["binding_count"] != len(entries)):
        raise ValidationError("invalid approved binding count or inventory")
    if (not isinstance(expected_peer_ids, list) or len(expected_peer_ids) > len(entries)
            or any(not isinstance(i, str) or not i for i in expected_peer_ids)
            or len(expected_peer_ids) != len(set(expected_peer_ids))):
        raise ValidationError("invalid selected identities")

    by_id = {}
    keys, addresses = set(), set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValidationError("invalid binding entry")
        ident, ips = entry.get("peer_id"), entry.get("allowed_ips")
        if (not isinstance(ident, str) or not ident or ident in by_id
                or not isinstance(ips, list) or len(ips) != 1):
            raise ValidationError("invalid peer identity or prefixes")
        key = check_key(entry.get("public_key"))
        prefix = _host_prefix(ips[0], network)
        if key in keys or prefix in addresses:
            raise ValidationError("duplicate approved key/address")
        by_id[ident] = (key, prefix)
        keys.add(key)
        addresses.add(prefix)
    if any(ident not in by_id for ident in expected_peer_ids):
        raise ValidationError("selected identity is not approved")
    expected = {by_id[ident][0]: by_id[ident][1] for ident in expected_peer_ids}
    observed = parse_allowedips_text(output, pool=str(network))
    missing = sorted(expected.keys() - observed.keys())
    unexpected = sorted(observed.keys() - expected.keys())
    mismatched = sorted(k for k in expected.keys() & observed.keys() if expected[k] != observed[k])
    return {
        "schema": SCHEMA,
        "text_matches_selected_intent": not (missing or unexpected or mismatched),
        "expected_count": len(expected),
        "observed_count": len(observed),
        "missing_public_keys": missing,
        "unexpected_public_keys": unexpected,
        "mismatched_public_keys": mismatched,
        "readback_source_authenticated": False,
        "active_kernel_state_attested": False,
        "applied": False,
        "data_plane_enforced": False,
        "warning": "A matching text snapshot is not authenticated kernel state or authorization.",
    }

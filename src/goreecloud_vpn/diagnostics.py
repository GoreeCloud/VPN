"""Read-only management diagnostics; never probe hosts or enforce packets."""
from collections import Counter
import ipaddress

from .core import ValidationError


def evaluate_access(peers, policies, source_id, target_id, protocol, port=None):
    """Explain a directional decision against one management-state snapshot."""
    if not isinstance(source_id, str) or not isinstance(target_id, str):
        raise ValidationError("invalid peer identity")
    if protocol not in ("tcp", "udp", "icmp"):
        raise ValidationError("invalid protocol")
    if (protocol == "icmp" and port is not None) or (protocol != "icmp" and (
        type(port) is not int or not 1 <= port <= 65535
    )):
        raise ValidationError("invalid port for protocol")
    # A corrupted or synthetic snapshot must never silently select the last
    # record for a duplicate identity when explaining an allow decision.
    ids = [peer["id"] for peer in peers]
    if len(ids) != len(set(ids)):
        raise ValidationError("duplicate peer identity in management snapshot")
    by_id = {peer["id"]: peer for peer in peers}
    source, target = by_id.get(source_id), by_id.get(target_id)
    matches = []
    if source is None or target is None:
        reason = "peer_not_found"
    elif source["status"] != "approved" or target["status"] != "approved":
        reason = "peer_not_approved"
    elif source_id == target_id:
        reason = "self_access_denied"
    else:
        matches = sorted(rule["id"] for rule in policies
                         if rule["source"] in source["groups"]
                         and rule["target"] in target["groups"]
                         and rule["protocol"] == protocol
                         and (protocol == "icmp" or port in rule["ports"]))
        reason = "matching_allow_policy" if matches else "default_deny"
    return {"allowed": bool(matches), "reason": reason,
            "matching_policy_ids": matches, "data_plane_enforced": False}


def simulate_access(store, checks):
    if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
        raise ValidationError("checks must contain 1 to 100 access queries")
    # Reject malformed batches before accessing any management-state reader.
    # This avoids unnecessary database work and prevents partial batches from
    # causing a snapshot read before their invalid entries are discovered.
    for check in checks:
        if (type(check) is not dict or
                set(check) - {"source_id", "target_id", "protocol", "port"}):
            raise ValidationError("invalid access query fields")
        if not isinstance(check.get("source_id"), str) or not isinstance(check.get("target_id"), str):
            raise ValidationError("invalid peer identity")
        protocol, port = check.get("protocol"), check.get("port")
        if protocol not in ("tcp", "udp", "icmp"):
            raise ValidationError("invalid protocol")
        if (protocol == "icmp" and port is not None) or (protocol != "icmp" and (
                type(port) is not int or not 1 <= port <= 65535)):
            raise ValidationError("invalid port for protocol")
    bounded_reader = getattr(store, "snapshot_bounded", None)
    if callable(bounded_reader):
        peers, policies = bounded_reader(max_peers=4096, max_policies=4096)
    else:
        peers, policies = store.snapshot()
    if (type(peers) is not list or type(policies) is not list
            or len(peers) > 4096 or len(policies) > 4096
            or len(peers) * len(policies) > 1_000_000):
        raise ValidationError("access simulation exceeds bounded input limits")
    results = []
    for check in checks:
        results.append(evaluate_access(peers, policies, check.get("source_id"),
                                       check.get("target_id"), check.get("protocol"), check.get("port")))
    return {"results": results, "data_plane_enforced": False}


def _pool_index(address):
    """Return the numeric host index, or None for an unreadable record."""
    try:
        return int(ipaddress.IPv4Address(address))
    except (ValueError, TypeError, OSError):
        return None


def management_status(store):
    peers, policies = store.snapshot()
    counts = Counter(peer["status"] for peer in peers)
    groups = {}
    for peer in peers:
        for group in peer["groups"]:
            groups.setdefault(group, Counter())[peer["status"]] += 1
    first = int(store.network.network_address) + 10
    last = int(store.network.broadcast_address) - 1
    in_pool = sum(record is not None and first <= record <= last
                  for record in (_pool_index(peer["address"]) for peer in peers))
    capacity = store.network.num_addresses - 11
    return {
        "component": "management", "maturity": "alpha",
        "peers": {"total": len(peers), **{s: counts[s] for s in ("pending", "approved", "revoked")}},
        "policy_count": len(policies), "dns_record_count": counts["approved"],
        "domain": store.domain,
        "address_pool": {"subnet": str(store.network), "capacity": capacity,
                         "allocated": in_pool, "available": capacity - in_pool,
                         "out_of_pool_records": len(peers) - in_pool,
                         "revoked_addresses_reusable": False},
        "groups": [{"name": name, **{s: groups[name][s] for s in ("pending", "approved", "revoked")}}
                   for name in sorted(groups)],
        "wireguard_tunnels_active": False, "data_plane_enforced": False,
        "dns_server_running": False,
        "warning": "Management records only; no live connectivity or protection is measured.",
    }


def policy_diagnostics(store):
    peers, policies = store.snapshot()
    members = {}
    for peer in peers:
        if peer["status"] == "approved":
            for group in peer["groups"]:
                members.setdefault(group, set()).add(peer["id"])
    signatures = {}
    findings = []
    for rule in policies:
        source = members.get(rule["source"], set())
        target = members.get(rule["target"], set())
        pairs = len(source) * len(target) - len(source & target)
        warnings = []
        if not source:
            warnings.append("no_approved_source_members")
        if not target:
            warnings.append("no_approved_target_members")
        if source and target and not pairs:
            warnings.append("no_distinct_peer_pairs")
        signature = (rule["source"], rule["target"], rule["protocol"], tuple(sorted(rule["ports"])))
        duplicates = signatures.setdefault(signature, [])
        duplicates.append(rule["id"])
        findings.append({"policy_id": rule["id"], "eligible_peer_pairs": pairs, "warnings": warnings})
    duplicate_sets = [sorted(ids) for ids in signatures.values() if len(ids) > 1]
    return {"policies": findings, "duplicate_policy_sets": sorted(duplicate_sets),
            "data_plane_enforced": False,
            "warning": "Static management diagnostics only; duplicate detection compares exact rules, not overlapping ports."}

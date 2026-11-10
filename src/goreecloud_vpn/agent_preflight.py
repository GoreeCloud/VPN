"""One-snapshot OFFLINE peer, policy and public-readback consistency preflight.

This module NEVER issues a network command, opens a socket, authenticates a
device, signs instructions or applies a firewall. A successful textual match
is not permission to deploy. No data-plane agent exists in this module.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from .core import ValidationError
from .firewall_preview import (
    _groups, _policy, build_nft_ingress_preview,
)
from .identity_binding import build_key_address_binding_intent
from .kernel_readback import compare_allowedips_to_intent

SCHEMA = "goreecloud.vpn.offline-ingress-preflight.v1"
# Keep policy-to-peer evaluation bounded before running preview compilers.
# These are offline input caps, NOT an assertion of deployable fleet scale.
MAX_PREFLIGHT_PEERS = 4096
MAX_PREFLIGHT_POLICIES = 4096
MAX_POLICY_PEER_EVALUATIONS = 1_000_000


class _FrozenSnapshot:
    """Adapt the *same* SQLite snapshot to existing nonapplying compilers."""

    def __init__(self, network, peers: list, policies: list):
        self.network = network
        self._peers = deepcopy(peers)
        self._policies = deepcopy(policies)

    def snapshot(self):
        return deepcopy(self._peers), deepcopy(self._policies)


def build_offline_ingress_preflight(
    store, target_peer_id: str, public_allowedips_text: str,
    *, interface: str = "wg0",
) -> dict:
    """Inspect a single, consistent generation without granting authority.

    Only peer IDs whose group policy allows inbound traffic to the target
    should appear in the specified incoming-only lab WireGuard peer set.
    Interfaces used for *outgoing* flows need a different interface contract.
    """
    if not isinstance(target_peer_id, str) or not target_peer_id:
        raise ValidationError("invalid target peer identifier")
    # Prefer source-side SQL limits when supported by the trusted VPNStore,
    # instead of loading the entire DB before checking Python list lengths.
    # Synthetic snapshot fixtures retain the legacy read contract.
    bounded_reader = getattr(store, "snapshot_bounded", None)
    if callable(bounded_reader):
        peers, policies = bounded_reader(
            max_peers=MAX_PREFLIGHT_PEERS, max_policies=MAX_PREFLIGHT_POLICIES
        )
    else:
        peers, policies = store.snapshot()
    if (type(peers) is not list or type(policies) is not list
            or len(peers) > MAX_PREFLIGHT_PEERS
            or len(policies) > MAX_PREFLIGHT_POLICIES
            or len(peers) * len(policies) > MAX_POLICY_PEER_EVALUATIONS):
        raise ValidationError("offline policy preflight exceeds bounded input limits")
    frozen = _FrozenSnapshot(store.network, peers, policies)
    manifest = build_key_address_binding_intent(frozen)
    firewall = build_nft_ingress_preview(
        frozen, target_peer_id, interface=interface
    )

    eligible = [p for p in peers if p.get("status") == "approved"]
    identifiers = [p.get("id") for p in eligible]
    if (any(not isinstance(i, str) or not i for i in identifiers)
            or len(identifiers) != len(set(identifiers))):
        raise ValidationError("duplicate or invalid approved peer identity")
    target = next((p for p in eligible if p["id"] == target_peer_id), None)
    if target is None:
        raise ValidationError("target is not an approved peer")

    target_groups = _groups(target.get("groups"))
    parsed_rules = [_policy(p) for p in policies]
    sources = []
    for peer in eligible:
        if peer["id"] == target_peer_id:
            continue
        source_groups = _groups(peer.get("groups"))
        if any(source in source_groups and dest in target_groups
               for source, dest, _, _ in parsed_rules):
            sources.append(peer["id"])
    sources.sort()

    comparison = compare_allowedips_to_intent(
        manifest, public_allowedips_text, expected_peer_ids=sources
    )
    if not comparison["text_matches_selected_intent"]:
        raise ValidationError(
            "public WireGuard peer readback differs from this frozen policy "
            "generation; refusing to produce an ingress bundle"
        )

    # Fingerprint protects against accidental local mixing only. No signing.
    bundle_content = {
        "schema": SCHEMA,
        "target_peer_id": target_peer_id,
        "interface": interface,
        "source_peer_ids": sources,
        "binding_snapshot_sha256": manifest["snapshot_sha256"],
        "policies": policies,
        "nftables_text": firewall["nftables_text"],
    }
    canonical = json.dumps(
        bundle_content, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "schema": SCHEMA,
        "target_peer_id": target_peer_id,
        "interface": interface,
        "source_peer_ids": sources,
        "allowed_source_count": len(sources),
        "binding_manifest": manifest,
        "public_text_comparison": comparison,
        "firewall_preview": firewall,
        "candidate_sha256": hashlib.sha256(canonical).hexdigest(),
        "candidate_sha256_is_authenticated": False,
        "single_snapshot_compiled": True,
        "kernel_readback_authenticated": False,
        "agent_invoked": False,
        "applied": False,
        "data_plane_enforced": False,
        "production_ready": False,
        "warning": (
            "Offline input consistency only. Not authenticated device "
            "enrollment, trustworthy kernel state, or authorization to apply."
        ),
    }

"""Test-only genuine X25519 proof-gated approvals; NEVER installed in the wheel.

Seeded deterministic private keys are ONLY synthetic fixture material. The
application never derives a peer private key from the public key; the test
knows its own seed and exercises the actual short-lived enrollment protocol.
"""
from __future__ import annotations

import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from goreecloud_vpn.enrollment import ProofChallenges, device_proof

_PRIVATE_BY_PUBLIC: dict[str, X25519PrivateKey] = {}


def key(seed: int) -> str:
    if type(seed) is not int or not 1 <= seed <= 255:
        raise ValueError("fixture seed must be a nonzero single byte")
    private = X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    _PRIVATE_BY_PUBLIC[public] = private
    return public


def prove_peer(store, peer: dict, *, proof_manager=None) -> bool:
    """Exercise the actual challenge flow but leave admin approval pending."""
    private = _PRIVATE_BY_PUBLIC.get(peer.get("public_key"))
    if private is None:
        raise AssertionError("test peer lacks a fixture-owned X25519 private key")
    manager = proof_manager if proof_manager is not None else ProofChallenges(store)
    challenge = manager.issue(peer["id"])
    if not manager.verify(peer["id"], challenge["challenge_id"],
                          device_proof(private, challenge)):
        raise AssertionError("test peer key possession was not verified")
    return True


def prove_and_approve(store, peer: dict) -> bool:
    """Run issue->real X25519/HKDF/HMAC proof->consume->approval in tests."""
    prove_peer(store, peer)
    return store.approve_peer(peer["id"])

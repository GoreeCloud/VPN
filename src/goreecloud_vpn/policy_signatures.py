"""Experimental offline Ed25519 policy-envelope *verification* only.

Never signs messages, provisions identity, changes networking, or stores replay
state. A caller MUST obtain trusted verification keys/audience/clock/monotonic
counter from separate authenticated, durable sources. NOT a VPN agent.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re

from .core import ValidationError

SCHEMA = "goreecloud.vpn.signed-policy-intent.ed25519.v1"
DOMAIN = b"GoreeCloud VPN policy intent verification v1\x00"
MAX_ENVELOPE_BYTES = 4096
MAX_POLICY_BYTES = 1_048_576
MAX_VALIDITY_SECONDS = 600
MAX_FUTURE_SKEW_SECONDS = 30
MAX_SEQUENCE = 2**63 - 1
_FIELDS = frozenset({
    "schema", "key_id", "audience", "sequence", "issued_at",
    "expires_at", "policy_sha256", "signature",
})
_KEY_ID = re.compile(r"[a-zA-Z0-9_-]{1,64}\Z")
_AUDIENCE = re.compile(r"goreecloud-agent:[a-zA-Z0-9_.:-]{1,96}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValidationError("duplicate policy envelope field")
        out[key] = value
    return out


def _nonfinite(value):
    raise ValidationError("nonfinite value in policy envelope")


def _canonical_claims(claims: dict) -> bytes:
    """Domain-separated, deterministic bytes signed by an independent authority."""
    return DOMAIN + json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def verify_offline_policy_signature(
    envelope: bytes,
    policy_payload: bytes,
    *,
    trusted_public_keys: dict[str, bytes],
    expected_audience: str,
    minimum_sequence: int,
    now: int,
) -> dict:
    """Verify offline intent, rejecting all untrusted/mismatched signatures.

    This is NOT anti-replay by itself: the caller must persist the highest
    accepted sequence *atomically with* any eventual state transition.
    Verification never authorizes a privileged command or packet enforcement.
    """
    if (not isinstance(envelope, bytes)
            or not 1 <= len(envelope) <= MAX_ENVELOPE_BYTES
            or not isinstance(policy_payload, bytes)
            or not 1 <= len(policy_payload) <= MAX_POLICY_BYTES):
        raise ValidationError("invalid or oversized signed policy input")
    if (not isinstance(trusted_public_keys, dict)
            or not 1 <= len(trusted_public_keys) <= 32
            or not isinstance(expected_audience, str)
            or not _AUDIENCE.fullmatch(expected_audience)
            or type(minimum_sequence) is not int
            or not 0 <= minimum_sequence <= MAX_SEQUENCE
            or type(now) is not int
            or not 0 <= now <= MAX_SEQUENCE):
        raise ValidationError("invalid trusted verification context")
    try:
        data = json.loads(
            envelope.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_nonfinite,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("malformed signed policy envelope") from exc
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise ValidationError("unexpected policy envelope schema or fields")

    key_id, audience = data["key_id"], data["audience"]
    seq, issued, expires = data["sequence"], data["issued_at"], data["expires_at"]
    digest, signature = data["policy_sha256"], data["signature"]
    if (data["schema"] != SCHEMA
            or not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
            or audience != expected_audience
            or type(seq) is not int or not minimum_sequence < seq <= MAX_SEQUENCE
            or type(issued) is not int or type(expires) is not int
            or not 0 <= issued <= MAX_SEQUENCE
            or not 0 <= expires <= MAX_SEQUENCE
            or expires <= issued or expires - issued > MAX_VALIDITY_SECONDS
            or issued > now + MAX_FUTURE_SKEW_SECONDS
            or expires <= now
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            or not isinstance(signature, str)):
        raise ValidationError("policy envelope claims are invalid or stale")

    public_bytes = trusted_public_keys.get(key_id)
    if (not isinstance(public_bytes, bytes) or len(public_bytes) != 32
            or any(not isinstance(k, str) or not _KEY_ID.fullmatch(k)
                   or not isinstance(v, bytes) or len(v) != 32
                   for k, v in trusted_public_keys.items())):
        raise ValidationError("unknown or invalid pretrusted signing key")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("invalid policy signature encoding") from exc
    if len(signature_bytes) != 64 or base64.b64encode(signature_bytes).decode("ascii") != signature:
        raise ValidationError("noncanonical policy signature")

    if not hmac.compare_digest(
        hashlib.sha256(policy_payload).hexdigest(), digest,
    ):
        raise ValidationError("policy payload differs from signed digest")

    # Optional install extra: cryptography>=50.0.2,<51, no own Ed25519 code.
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValidationError("policy signature verification dependency is unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature_bytes, _canonical_claims({k: v for k, v in data.items() if k != "signature"})
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValidationError("policy signing signature is not valid") from exc

    return {
        "schema": SCHEMA,
        "key_id": key_id,
        "audience": audience,
        "sequence": seq,
        "expires_at": expires,
        "signature_verified": True,
        "policy_bytes_digest_verified": True,
        "replay_state_persisted": False,
        "enrollment_authenticated": False,
        "kernel_state_attested": False,
        "agent_invoked": False,
        "applied": False,
        "data_plane_enforced": False,
        "warning": (
            "Offline signature checks alone do not establish agent authority. "
            "Trusted key distribution, atomic durable anti-replay state and an "
            "independently reviewed production agent remain unimplemented."
        ),
    }

"""Offline, short-lived WireGuard X25519 key-possession challenge protocol.

This proves control of the registered WireGuard private key to the local
management service. It is NOT a remote enrollment transport, user authentication,
TLS, host attestation, or a production device identity system.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core import VPNStore, ValidationError, check_key

PROTOCOL = "goreecloud.vpn.key-possession.v1"
_INFO = b"goreecloud-vpn/peer-key-possession/v1"
_FIELDS = ("protocol", "peer_id", "challenge_id", "nonce", "server_public_key", "peer_public_key")
_ALLOWED_CHALLENGE_FIELDS = frozenset((*_FIELDS, "expires_in_seconds"))
_MAX_CHALLENGE_FIELD_CHARS = 128
_MAX_TRANSCRIPT_BYTES = 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: object, length: int, field: str) -> bytes:
    if not isinstance(value, str) or len(value) > 128:
        raise ValidationError("invalid " + field)
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("invalid " + field) from exc
    if len(result) != length:
        raise ValidationError("invalid " + field)
    return result


def _public_bytes(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _transcript(challenge: dict) -> bytes:
    if not isinstance(challenge, dict) or challenge.get("protocol") != PROTOCOL:
        raise ValidationError("invalid challenge protocol")
    # This object may arrive over an untrusted out-of-band channel. Reject
    # ambiguous extensions and oversized/nonprinting values before ECDH.
    if not set(challenge).issubset(_ALLOWED_CHALLENGE_FIELDS):
        raise ValidationError("unexpected challenge fields")
    if any(not isinstance(challenge.get(k), str)
           or not 1 <= len(challenge[k]) <= _MAX_CHALLENGE_FIELD_CHARS
           or not challenge[k].isascii() or not challenge[k].isprintable()
           for k in _FIELDS):
        raise ValidationError("invalid challenge fields")
    if "expires_in_seconds" in challenge:
        ttl = challenge["expires_in_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= 600:
            raise ValidationError("invalid challenge expiry metadata")
    transcript = json.dumps(
        {key: challenge[key] for key in _FIELDS},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    if len(transcript) > _MAX_TRANSCRIPT_BYTES:
        raise ValidationError("challenge transcript too large")
    return transcript


def _digest(shared: bytes, nonce: bytes, transcript: bytes) -> bytes:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=_INFO).derive(shared)
    return hmac.new(key, transcript, hashlib.sha256).digest()


def device_proof(device_private_key: X25519PrivateKey, challenge: dict) -> str:
    """Run only on the device holding the private key; never send that key to the server."""
    if not isinstance(device_private_key, X25519PrivateKey):
        raise ValidationError("device key must be an X25519 private-key object")
    message = _transcript(challenge)
    nonce = _decode(challenge["nonce"], 32, "nonce")
    server_key = _decode(challenge["server_public_key"], 32, "server public key")
    peer_key = _decode(challenge["peer_public_key"], 32, "peer public key")
    if _public_bytes(device_private_key) != peer_key:
        raise ValidationError("challenge does not match the device public key")
    try:
        shared = device_private_key.exchange(X25519PublicKey.from_public_bytes(server_key))
    except ValueError as exc:
        raise ValidationError("invalid server public key") from exc
    return _b64(_digest(shared, nonce, message))


class ProofChallenges:
    """Memory-bounded single-use challenge cache scoped to one management process."""

    def __init__(self, store: VPNStore, *, ttl_seconds: int = 120, max_pending: int = 256,
                 clock=None):
        self.store = store
        if not 1 <= ttl_seconds <= 600 or not 1 <= max_pending <= 4096:
            raise ValueError("invalid challenge limits")
        self.ttl = ttl_seconds
        self.limit = max_pending
        self.clock = clock if clock is not None else time.monotonic
        self.lock = threading.RLock()
        self.pending: dict[str, tuple[str, str, bytes, float]] = {}

    def issue(self, peer_id: str) -> dict:
        peer = self.store.pending_peer(peer_id)
        check_key(peer["public_key"])
        nonce = secrets.token_bytes(32)
        ephemeral = X25519PrivateKey.generate()
        server_public = _public_bytes(ephemeral)
        challenge = {
            "protocol": PROTOCOL,
            "peer_id": peer["id"],
            "challenge_id": secrets.token_urlsafe(24),
            "nonce": _b64(nonce),
            "server_public_key": _b64(server_public),
            "peer_public_key": peer["public_key"],
        }
        try:
            shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(
                _decode(peer["public_key"], 32, "peer public key")
            ))
        except ValueError as exc:
            raise ValidationError("peer public key cannot be used for X25519 exchange") from exc
        expected = _digest(shared, nonce, _transcript(challenge))
        with self.lock:
            self._prune()
            for identifier, (subject, _, _, _) in list(self.pending.items()):
                if subject == peer_id:
                    del self.pending[identifier]
            if len(self.pending) >= self.limit:
                raise ValidationError("too many active enrollment challenges")
            self.pending[challenge["challenge_id"]] = (
                peer_id, peer["public_key"], expected, self.clock() + self.ttl,
            )
        challenge["expires_in_seconds"] = self.ttl
        return challenge

    def verify(self, peer_id: str, challenge_id: object, proof: object) -> bool:
        if not isinstance(peer_id, str) or not isinstance(challenge_id, str):
            return False
        # Consume even malformed proofs: each challenge has exactly one attempt.
        with self.lock:
            self._prune()
            item = self.pending.pop(challenge_id, None)
        if item is None:
            return False
        subject, public_key, expected, expiration = item
        if subject != peer_id or self.clock() >= expiration:
            return False
        try:
            provided = _decode(proof, 32, "proof")
        except ValidationError:
            return False
        if not hmac.compare_digest(provided, expected):
            return False
        return self.store.record_device_proof(peer_id, public_key)

    def _prune(self) -> None:
        """Call while holding self.lock."""
        now = self.clock()
        for identifier, (_, _, _, expiry) in list(self.pending.items()):
            if now >= expiry:
                del self.pending[identifier]

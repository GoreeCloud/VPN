"""Offline Ed25519 signing-key segregation and fail-closed verifier tests.

Only ephemeral in-memory test signing keys. Never provision production keys.
"""
import base64
import copy
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from goreecloud_vpn.core import ValidationError
from goreecloud_vpn.policy_signatures import (
    SCHEMA, MAX_POLICY_BYTES, _canonical_claims, verify_offline_policy_signature,
)

_UNSET = object()


class SignedPolicyEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.other_key = Ed25519PrivateKey.generate()
        self.trusted_public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.other_public = self.other_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.now = 1800000000
        self.policy = b'{"schema":"policy-v1","deny_by_default":true}'
        self.claims = {
            "schema": SCHEMA,
            "key_id": "controller-key-1",
            "audience": "goreecloud-agent:node-1",
            "sequence": 42,
            "issued_at": self.now - 10,
            "expires_at": self.now + 120,
            "policy_sha256": hashlib.sha256(self.policy).hexdigest(),
        }
        self.context = {
            "trusted_public_keys": {"controller-key-1": self.trusted_public},
            "expected_audience": "goreecloud-agent:node-1",
            "minimum_sequence": 41,
            "now": self.now,
        }

    def envelope(self, *, claims=None, sign_key=None):
        claims = self.claims if claims is None else claims
        private = self.key if sign_key is None else sign_key
        signed = dict(claims)
        signed["signature"] = base64.b64encode(
            private.sign(_canonical_claims(claims))
        ).decode("ascii")
        return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("ascii")

    def verify(self, data=_UNSET, policy=_UNSET, **context):
        return verify_offline_policy_signature(
            self.envelope() if data is _UNSET else data,
            self.policy if policy is _UNSET else policy,
            **(self.context | context),
        )

    def test_accepts_exact_separate_ed25519_signing_key_and_never_applies(self):
        result = self.verify()
        self.assertTrue(result["signature_verified"])
        self.assertTrue(result["policy_bytes_digest_verified"])
        self.assertEqual(result["sequence"], 42)
        self.assertFalse(result["replay_state_persisted"])
        self.assertFalse(result["enrollment_authenticated"])
        self.assertFalse(result["kernel_state_attested"])
        self.assertFalse(result["agent_invoked"])
        self.assertFalse(result["applied"])
        self.assertFalse(result["data_plane_enforced"])

    def test_valid_signature_cannot_change_audience_or_claims(self):
        signed = json.loads(self.envelope())
        for field, value in [
            ("audience", "goreecloud-agent:node-2"),
            ("sequence", 43),
            ("expires_at", self.now + 200),
            ("key_id", "unknown"),
            ("policy_sha256", "a"*64),
        ]:
            with self.subTest(field=field):
                tampered = dict(signed)
                tampered[field] = value
                with self.assertRaises(ValidationError):
                    self.verify(json.dumps(tampered).encode())

    def test_separate_trusted_key_required_not_provided_by_envelope(self):
        for mapping in (
            {}, {"controller-key-1": self.other_public},
            {"different-key": self.trusted_public},
            {"controller-key-1": b"short"},
        ):
            with self.subTest(mapping=mapping), self.assertRaises(ValidationError):
                self.verify(trusted_public_keys=mapping)

    def test_other_signer_cannot_impersonate_trusted_key(self):
        with self.assertRaises(ValidationError):
            self.verify(self.envelope(sign_key=self.other_key))

    def test_modified_policy_bytes_or_hash_are_rejected(self):
        with self.assertRaises(ValidationError):
            self.verify(policy=self.policy + b" ")
        with self.assertRaises(ValidationError):
            self.verify(policy=b"other but same envelope")

    def test_wrong_expected_recipient_rejected(self):
        with self.assertRaises(ValidationError):
            self.verify(expected_audience="goreecloud-agent:node-2")

    def test_old_equal_or_boolean_sequence_rejected(self):
        for seq in (40, 41, False, -1, 2**63):
            claims = dict(self.claims, sequence=seq)
            with self.subTest(seq=seq), self.assertRaises(ValidationError):
                self.verify(self.envelope(claims=claims))
        with self.assertRaises(ValidationError):
            self.verify(minimum_sequence=42)
        with self.assertRaises(ValidationError):
            self.verify(minimum_sequence=True)

    def test_expired_future_issued_and_long_lived_rejected(self):
        for field, val in [
            ("expires_at", self.now),
            ("expires_at", self.now - 1),
            ("expires_at", self.now + 601),
            ("expires_at", self.now - 10),
            ("issued_at", self.now + 31),
            ("issued_at", -1),
            ("issued_at", True),
            ("issued_at", 2**63),
            ("expires_at", 2**63),
        ]:
            claims = dict(self.claims, **{field: val})
            with self.subTest(field=field, val=val), self.assertRaises(ValidationError):
                self.verify(self.envelope(claims=claims))

    def test_timestamp_skew_and_ttl_boundaries(self):
        claims = dict(self.claims, issued_at=self.now + 30, expires_at=self.now + 60)
        self.assertTrue(self.verify(self.envelope(claims=claims))["signature_verified"])
        claims = dict(self.claims, issued_at=self.now - 599, expires_at=self.now + 1)
        self.assertTrue(self.verify(self.envelope(claims=claims))["signature_verified"])

    def test_reject_unknown_missing_or_invalid_schema(self):
        for field, value in [
            ("schema", "other"), ("schema", 1),
            ("key_id", "controller/key"),
            ("audience", "other"),
            ("signature", 123),
            ("policy_sha256", "ABCDEF"),
        ]:
            raw = json.loads(self.envelope())
            raw[field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.verify(json.dumps(raw).encode())
        raw = json.loads(self.envelope())
        del raw["audience"]
        with self.assertRaises(ValidationError):
            self.verify(json.dumps(raw).encode())
        raw = json.loads(self.envelope())
        raw["extra"] = "allow"
        with self.assertRaises(ValidationError):
            self.verify(json.dumps(raw).encode())

    def test_duplicate_json_fields_and_nan_rejected(self):
        signed = self.envelope().decode()
        injected = '{"key_id":"controller-key-1",' + signed[1:]
        with self.assertRaises(ValidationError):
            self.verify(injected.encode())
        nan = signed.replace('"sequence":42', '"sequence":NaN')
        with self.assertRaises(ValidationError):
            self.verify(nan.encode())

    def test_signature_base64_and_length_strict(self):
        raw = json.loads(self.envelope())
        for bad in ("x", "", "***", raw["signature"] + "=", "AA=="):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                self.verify(json.dumps({**raw, "signature": bad}).encode())

    def test_size_unicode_and_payload_types_rejected(self):
        for raw in (b"", b" "*4097, b"\xff", [], None):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(ValidationError):
                self.verify(raw)
        for payload in (b"", b"X"*(MAX_POLICY_BYTES+1), None, "not bytes"):
            with self.subTest(payload=type(payload).__name__), self.assertRaises(ValidationError):
                self.verify(policy=payload)

    def test_invalid_verification_context_rejected(self):
        for context in (
            {"expected_audience": "not-an-agent"},
            {"expected_audience": 1},
            {"trusted_public_keys": {"controller-key-1": self.trusted_public, "bad/other": self.other_public}},
            {"minimum_sequence": -1},
            {"now": True},
            {"now": -1},
            {"now": 2**63},
        ):
            with self.subTest(context=list(context)), self.assertRaises(ValidationError):
                self.verify(**context)

    def test_different_key_id_requires_pretrusted_rotation(self):
        second_claims = dict(self.claims, key_id="controller-key-2", sequence=43)
        second_envelope = self.envelope(claims=second_claims, sign_key=self.other_key)
        with self.assertRaises(ValidationError):
            self.verify(second_envelope)
        approved = self.verify(
            second_envelope, trusted_public_keys={
                "controller-key-1": self.trusted_public,
                "controller-key-2": self.other_public,
            },
        )
        self.assertEqual(approved["key_id"], "controller-key-2")


if __name__ == "__main__":
    unittest.main()

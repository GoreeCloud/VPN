"""DRAFT-only test: signed offline claims + SQLite revision CAS, never an agent.

This is a demonstration of two independent modules, NOT a deployable
security protocol or permission to modify WireGuard/nftables.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from goreecloud_vpn.core import ValidationError
from goreecloud_vpn.policy_revision_ledger import OfflinePolicyRevisionLedger
from goreecloud_vpn.policy_signatures import SCHEMA, _canonical_claims, verify_offline_policy_signature

AUDIENCE = "goreecloud-agent:lab-one"
NOW = 1800000000
POLICY = b'{"deny_by_default":true,"schema":"offline-test-only"}'


class NonapplyingSignedRevisionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-signed-ledger.")
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.first = Ed25519PrivateKey.generate()
        self.second = Ed25519PrivateKey.generate()
        self.keys = {
            "signer-first": self.first.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "signer-second": self.second.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        }

    def tearDown(self):
        self.temp.cleanup()

    def envelope(self, *, seq, key="signer-first", audience=AUDIENCE, payload=POLICY, now=NOW):
        claims = {
            "schema": SCHEMA, "key_id": key, "audience": audience,
            "sequence": seq, "issued_at": now-10, "expires_at": now+100,
            "policy_sha256": sha256(payload).hexdigest(),
        }
        private = self.first if key == "signer-first" else self.second
        signature = base64.b64encode(private.sign(_canonical_claims(claims))).decode("ascii")
        return json.dumps({**claims,"signature":signature},sort_keys=True).encode("ascii")

    def checked_accept(self, ledger, envelope, *, policy=POLICY, keys=None,
                       expected_audience=AUDIENCE, now=NOW, after_verification=None):
        floor = ledger.read(audience=expected_audience)
        verified = verify_offline_policy_signature(
            envelope, policy,
            trusted_public_keys=self.keys if keys is None else keys,
            expected_audience=expected_audience, minimum_sequence=floor, now=now,
        )
        if after_verification is not None:
            after_verification()
        stored = ledger.compare_and_advance(
            key_id=verified["key_id"],
            audience=verified["audience"],
            expected_previous=floor,
            next_sequence=verified["sequence"],
            payload_sha256=sha256(policy).hexdigest(),
        )
        self.assertEqual(stored, verified["sequence"])
        self.assertFalse(verified["applied"])
        self.assertFalse(verified["agent_invoked"])
        self.assertFalse(verified["kernel_state_attested"])
        self.assertFalse(verified["data_plane_enforced"])
        return verified

    def test_valid_independently_trusted_signature_records_only_local_floor(self):
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            verified = self.checked_accept(ledger, self.envelope(seq=2))
            self.assertTrue(verified["signature_verified"])
            self.assertEqual(ledger.read(audience=AUDIENCE),2)
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["ledger.sqlite3"])

    def test_identical_or_older_signed_message_never_replays(self):
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            self.checked_accept(ledger,self.envelope(seq=7))
            for seq in (7,6,1):
                with self.subTest(seq=seq), self.assertRaises(ValidationError):
                    self.checked_accept(ledger,self.envelope(seq=seq))
            self.assertEqual(ledger.read(audience=AUDIENCE),7)

    def test_key_rotation_cannot_reset_counter_or_replay(self):
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            self.checked_accept(ledger,self.envelope(seq=30))
            with self.assertRaises(ValidationError):
                self.checked_accept(ledger,self.envelope(seq=1,key="signer-second"))
            self.checked_accept(ledger,self.envelope(seq=31,key="signer-second"))
            self.assertEqual(ledger.read(audience=AUDIENCE),31)

    def test_modified_policy_or_signature_does_not_consume_revision(self):
        source=self.envelope(seq=5)
        tampered=json.loads(source)
        tampered["sequence"]=6
        bad=[(source,b"corrupt"),(json.dumps(tampered).encode("ascii"),POLICY)]
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            for envelope,payload in bad:
                with self.assertRaises(ValidationError):
                    self.checked_accept(ledger,envelope,policy=payload)
            self.assertEqual(ledger.read(audience=AUDIENCE),0)
            self.checked_accept(ledger,source)

    def test_untrusted_signer_or_wrong_recipient_never_advances(self):
        source=self.envelope(seq=10)
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            with self.assertRaises(ValidationError):
                self.checked_accept(ledger,source,keys={"signer-second":self.keys["signer-second"]})
            with self.assertRaises(ValidationError):
                self.checked_accept(ledger,source,expected_audience="goreecloud-agent:other")
            self.assertEqual(ledger.read(audience=AUDIENCE),0)

    def test_expired_signature_never_advances(self):
        source=self.envelope(seq=10)
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            with self.assertRaises(ValidationError):
                self.checked_accept(ledger,source,now=NOW+200)
            self.assertEqual(ledger.read(audience=AUDIENCE),0)

    def test_racing_signed_claims_from_two_connections_one_fails_closed(self):
        barrier=threading.Barrier(2)
        outcomes=[]
        lock=threading.Lock()
        signed1=self.envelope(seq=11)
        signed2=self.envelope(seq=12,key="signer-second")

        def attempt(message):
            with OfflinePolicyRevisionLedger(self.path) as ledger:
                try:
                    self.checked_accept(
                        ledger,message,
                        after_verification=lambda: barrier.wait(timeout=5),
                    )
                    result="accepted"
                except ValidationError:
                    result="rejected"
            with lock:
                outcomes.append(result)

        t1=threading.Thread(target=attempt,args=(signed1,))
        t2=threading.Thread(target=attempt,args=(signed2,))
        t1.start();t2.start()
        t1.join(timeout=10);t2.join(timeout=10)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())
        self.assertEqual(sorted(outcomes),["accepted","rejected"])
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            self.assertIn(ledger.read(audience=AUDIENCE),(11,12))

    def test_db_restore_defeats_replay_floor_and_must_remain_release_gate(self):
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            self.checked_accept(ledger,self.envelope(seq=10))
        snapshot=self.path.read_bytes()
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            self.checked_accept(ledger,self.envelope(seq=20))
        self.path.write_bytes(snapshot)
        with OfflinePolicyRevisionLedger(self.path) as ledger:
            # Explicitly prove this is NOT hardware-protected anti-rollback.
            self.assertEqual(ledger.read(audience=AUDIENCE),10)


if __name__=="__main__":
    unittest.main()

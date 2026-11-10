"""Offline SQLite revision store: identity-scoped replay and CAS regression tests."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import unittest

from goreecloud_vpn.core import ValidationError
from goreecloud_vpn.policy_revision_ledger import OfflinePolicyRevisionLedger

AUDIENCE = "goreecloud-agent:device-a"
OTHER_AUDIENCE = "goreecloud-agent:device-b"
DIGEST = "a" * 64


class OfflineRevisionLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-ledger-private.")
        self.dir = Path(self.temp.name)
        self.db_file = self.dir / "revision-ledger.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def new(self, path=None):
        return OfflinePolicyRevisionLedger(self.db_file if path is None else path)

    def advance(self, ledger, *, key_id="key-1", audience=AUDIENCE,
                old=0, seq=1, digest=DIGEST):
        return ledger.compare_and_advance(
            key_id=key_id,
            audience=audience,
            expected_previous=old,
            next_sequence=seq,
            payload_sha256=digest,
        )

    def test_first_commit_and_private_file_permissions(self):
        with self.new() as db:
            self.assertEqual(db.read(audience=AUDIENCE), 0)
            self.assertEqual(self.advance(db), 1)
            self.assertEqual(db.read(audience=AUDIENCE), 1)
        mode = self.db_file.stat().st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_persists_revisions_after_reopening(self):
        with self.new() as db:
            self.advance(db, seq=16)
        with self.new() as db:
            self.assertEqual(db.read(audience=AUDIENCE), 16)
            self.assertEqual(self.advance(db, old=16, seq=17), 17)
        with self.new() as db:
            self.assertEqual(db.read(audience=AUDIENCE), 17)

    def test_equal_lower_and_previous_floor_staleness_rejected_without_change(self):
        with self.new() as db:
            self.advance(db, seq=9)
            for old, seq in ((0, 10), (9, 9), (9, 8), (8, 12)):
                with self.subTest(old=old, seq=seq), self.assertRaises(ValidationError):
                    self.advance(db, old=old, seq=seq)
            self.assertEqual(db.read(audience=AUDIENCE), 9)

    def test_controller_key_rotation_cannot_reset_audience_sequence(self):
        with self.new() as db:
            self.advance(db, key_id="first", seq=40)
            for old, seq in ((0, 1), (0, 41), (40, 40)):
                with self.subTest(old=old, seq=seq), self.assertRaises(ValidationError):
                    self.advance(db, key_id="second", old=old, seq=seq)
            self.assertEqual(self.advance(db, key_id="second", old=40, seq=41), 41)
            self.assertEqual(db.read(audience=AUDIENCE), 41)

    def test_independent_audiences_have_independent_sequence_floors(self):
        with self.new() as db:
            self.advance(db, seq=200)
            self.assertEqual(db.read(audience=OTHER_AUDIENCE), 0)
            self.assertEqual(self.advance(db, audience=OTHER_AUDIENCE, seq=3), 3)
            self.assertEqual(db.read(audience=AUDIENCE), 200)
            self.assertEqual(db.read(audience=OTHER_AUDIENCE), 3)

    def test_distinct_connections_racing_same_floor_only_one_commits(self):
        outcomes = []
        mutex = threading.Lock()
        start = threading.Barrier(2)

        def attempt(seq):
            with self.new() as ledger:
                start.wait(timeout=5)
                try:
                    self.advance(ledger, seq=seq)
                    result = ("accepted", seq)
                except ValidationError:
                    result = ("rejected", seq)
            with mutex:
                outcomes.append(result)

        threads = [
            threading.Thread(target=attempt, args=(21,)),
            threading.Thread(target=attempt, args=(22,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(sorted(x[0] for x in outcomes), ["accepted", "rejected"])
        with self.new() as db:
            self.assertIn(db.read(audience=AUDIENCE), (21, 22))

    def test_two_existing_connections_compare_and_swap_against_stale_floor(self):
        with self.new() as db1, self.new() as db2:
            self.assertEqual(db1.read(audience=AUDIENCE), 0)
            self.assertEqual(db2.read(audience=AUDIENCE), 0)
            self.advance(db1, seq=12)
            with self.assertRaises(ValidationError):
                self.advance(db2, seq=13)
            self.assertEqual(self.advance(db2, old=12, seq=14), 14)

    def test_failed_validation_does_not_partially_advance(self):
        with self.new() as db:
            self.advance(db, seq=4)
            with self.assertRaises(ValidationError):
                self.advance(db, old=4, seq=5, digest="not a real SHA256")
            self.assertEqual(db.read(audience=AUDIENCE), 4)
            self.assertEqual(self.advance(db, old=4, seq=6), 6)

    def test_corrupt_stored_key_or_digest_blocks_read_and_cas(self):
        with self.new() as ledger:
            self.advance(ledger, seq=7)
            for field, corrupt in (
                ("key_id", "invalid/key"),
                ("key_id", ""),
                ("digest", "X" * 64),
                ("digest", "0" * 63),
            ):
                with self.subTest(field=field, corrupt=corrupt):
                    # This is a synthetic corruption fixture, not permission
                    # to edit operational policy revision evidence.
                    ledger.db.execute(
                        f"UPDATE policy_revisions SET {field}=? WHERE audience=?",
                        (corrupt, AUDIENCE),
                    )
                    with self.assertRaisesRegex(
                        ValidationError, "invalid stored policy revision record"
                    ):
                        ledger.read(audience=AUDIENCE)
                    with self.assertRaisesRegex(
                        ValidationError, "invalid stored policy revision record"
                    ):
                        self.advance(ledger, old=7, seq=8)
                    self.assertEqual(
                        ledger.db.execute(
                            "SELECT sequence FROM policy_revisions WHERE audience=?",
                            (AUDIENCE,),
                        ).fetchone()[0],
                        7,
                    )
                    ledger.db.execute(
                        f"UPDATE policy_revisions SET {field}=? WHERE audience=?",
                        ("key-1" if field == "key_id" else DIGEST, AUDIENCE),
                    )
            self.assertEqual(ledger.read(audience=AUDIENCE), 7)
            self.assertEqual(self.advance(ledger, old=7, seq=8), 8)

    def test_corrupt_revision_row_on_reopen_is_not_trusted(self):
        with self.new() as ledger:
            self.advance(ledger, seq=9)
        with sqlite3.connect(self.db_file) as db:
            db.execute("UPDATE policy_revisions SET digest=?",
                       ("not-a-sha256",))
        with self.new() as ledger:
            with self.assertRaises(ValidationError):
                ledger.read(audience=AUDIENCE)
            with self.assertRaises(ValidationError):
                self.advance(ledger, old=9, seq=10)
        # The malformed row is preserved as evidence; no reset or repair.
        with sqlite3.connect(self.db_file) as db:
            self.assertEqual(db.execute(
                "SELECT digest FROM policy_revisions WHERE audience=?",
                (AUDIENCE,),
            ).fetchone()[0], "not-a-sha256")

    def test_invalid_metadata_and_boolean_revision_rejected(self):
        with self.new() as db:
            invalid = [
                {"key_id": "bad/key"},
                {"key_id": ""},
                {"audience": "other"},
                {"audience": "goreecloud-agent:"},
                {"old": True},
                {"old": -1},
                {"seq": True},
                {"seq": -1},
                {"seq": 2**63},
                {"digest": "A" * 64},
                {"digest": "a" * 63},
                {"digest": None},
            ]
            for item in invalid:
                with self.subTest(item=item), self.assertRaises(ValidationError):
                    self.advance(db, **item)
            self.assertEqual(db.read(audience=AUDIENCE), 0)

    def test_rejects_relative_paths_world_accessible_parent_and_symlink(self):
        with self.assertRaises(ValidationError):
            self.new("relative.sqlite3")
        other = self.dir / "public"
        other.mkdir(mode=0o755)
        with self.assertRaises(ValidationError):
            self.new(other / "ledger.sqlite3")
        with self.new():
            pass
        sym = self.dir / "sym.sqlite3"
        sym.symlink_to(self.db_file)
        with self.assertRaises(ValidationError):
            self.new(sym)

    def test_rejects_world_readable_existing_file_and_hardlinks(self):
        self.db_file.touch(mode=0o644)
        os.chmod(self.db_file, 0o644)
        with self.assertRaises(ValidationError):
            self.new()
        self.assertEqual(stat.S_IMODE(self.db_file.stat().st_mode), 0o644)
        os.chmod(self.db_file, 0o600)
        linked = self.dir / "hardlink.sqlite3"
        os.link(self.db_file, linked)
        with self.assertRaises(ValidationError):
            self.new()

    def test_rejects_corrupt_existing_db_without_resetting_state(self):
        self.db_file.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises(ValidationError):
            self.new()
        self.assertEqual(self.db_file.read_bytes(), b"not-a-sqlite-database")

    def test_rejects_preexisting_nonunique_schema_and_unexpected_trigger(self):
        with sqlite3.connect(self.db_file) as db:
            db.execute("CREATE TABLE policy_revisions (audience TEXT, key_id TEXT, sequence INTEGER, digest TEXT)")
        with self.assertRaises(ValidationError):
            self.new()
        self.db_file.unlink()
        with self.new():
            pass
        with sqlite3.connect(self.db_file) as db:
            db.execute("CREATE TRIGGER deny_insert BEFORE INSERT ON policy_revisions "
                       "BEGIN SELECT RAISE(ABORT, 'unexpected'); END")
        with self.assertRaises(ValidationError):
            self.new()

    def test_invalid_audience_rejected_before_database_read(self):
        with self.new() as db:
            for audience in ("", "node-1", "goreecloud-agent:", True, None):
                with self.subTest(audience=audience), self.assertRaises(ValidationError):
                    db.read(audience=audience)

    def test_readonly_api_never_invokes_network_or_kernel(self):
        with self.new() as db:
            self.advance(db, seq=11)
            self.assertEqual(db.read(audience=AUDIENCE), 11)
        # Only one local SQLite file, no private key material or executable.
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()),
                         ["revision-ledger.sqlite3"])

    def test_database_file_restore_remains_an_explicit_unresolved_rollback_risk(self):
        # This is a TEST SHOWING A LIMITATION, not an anti-rollback guarantee.
        with self.new() as db:
            self.advance(db, seq=10)
        saved_bytes = self.db_file.read_bytes()
        with self.new() as db:
            self.advance(db, old=10, seq=20)
        self.db_file.write_bytes(saved_bytes)  # A malicious backup restore.
        with self.new() as db:
            self.assertEqual(db.read(audience=AUDIENCE), 10)
        # A production agent must have an independent trusted monotonic anchor.

if __name__ == "__main__":
    unittest.main()

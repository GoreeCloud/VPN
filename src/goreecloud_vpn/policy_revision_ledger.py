"""Experimental OFFLINE sequence high-water storage, not agent authorization.

A local SQLite compare-and-swap ledger for independently verified policy
revisions. The floor is PER AUDIENCE across controller key rotations. No signature verification, kernel commands, network access,
external trust anchors or verified policy application happen here.

SQLite durable commits are NOT rollback-proof against a restored database,
compromised OS, stolen device, moved/copied directory, or clock rollback.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sqlite3
import stat

from .core import ValidationError

_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_AUDIENCE = re.compile(r"goreecloud-agent:[A-Za-z0-9_.:-]{1,96}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_MAX_SEQ = 2**63 - 1


def _check_id(key_id: str, audience: str) -> None:
    if (not isinstance(key_id, str) or not _KEY.fullmatch(key_id)
            or not isinstance(audience, str) or not _AUDIENCE.fullmatch(audience)):
        raise ValidationError("invalid policy sequence ledger identity")


def _check_seq(value: int) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SEQ:
        raise ValidationError("invalid policy sequence ledger revision")
    return value


def _check_stored_record(row: tuple) -> int:
    """Reject malformed stored identity/digest before trusting its sequence.

    This validates *format only*. A privileged writer can replace a complete,
    well-formed row or restore an old database; neither is authenticated.
    """
    if not isinstance(row, tuple) or len(row) != 3:
        raise ValidationError("invalid stored policy revision record")
    stored_key, sequence, stored_digest = row
    if (not isinstance(stored_key, str) or not _KEY.fullmatch(stored_key)
            or type(sequence) is not int or not 1 <= sequence <= _MAX_SEQ
            or not isinstance(stored_digest, str)
            or not _HEX.fullmatch(stored_digest)):
        raise ValidationError("invalid stored policy revision record")
    return sequence


class OfflinePolicyRevisionLedger:
    """One explicitly private user-owned DB; one owner of local revision state.

    This object is NOT a credential store. The caller, not this class, must
    verify signatures and atomically connect any future enforcement transition.
    """

    def __init__(self, path: str | Path) -> None:
        try:
            db_path = Path(path)
        except (TypeError, ValueError) as exc:
            raise ValidationError("invalid ledger path") from exc
        if (not db_path.is_absolute() or db_path.name in {"", ".", ".."}
                or not db_path.name.endswith(".sqlite3")
                or not 1 <= len(db_path.name) <= 128):
            raise ValidationError("ledger requires a dedicated absolute sqlite3 path")
        self.path = db_path
        directory = db_path.parent
        try:
            parent = os.stat(directory, follow_symlinks=False)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                    or parent.st_mode & 0o077):
                raise ValidationError("ledger parent must be an owner-only directory")
            if db_path.is_symlink():
                raise ValidationError("ledger database cannot be a symlink")
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(db_path, flags, 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1 or info.st_mode & 0o077):
                    raise ValidationError("ledger database must be private and uniquely linked")
            finally:
                os.close(fd)
        except (OSError, sqlite3.Error) as exc:
            raise ValidationError("cannot securely open policy revision ledger") from exc
        try:
            self.db = sqlite3.connect(str(db_path), timeout=5, isolation_level=None)
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA trusted_schema=OFF")
            with self.db:
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS policy_revisions ("
                    " audience TEXT PRIMARY KEY, key_id TEXT NOT NULL,"
                    " sequence INTEGER NOT NULL CHECK(sequence>=1),"
                    " digest TEXT NOT NULL)"
                )
                columns = self.db.execute(
                    "PRAGMA table_info(policy_revisions)"
                ).fetchall()
                if [(c[1], c[2], c[5]) for c in columns] != [
                    ("audience", "TEXT", 1), ("key_id", "TEXT", 0),
                    ("sequence", "INTEGER", 0), ("digest", "TEXT", 0),
                ]:
                    raise ValidationError("unexpected or corrupted ledger schema")
                if self.db.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                    "AND tbl_name='policy_revisions'"
                ).fetchone()[0]:
                    raise ValidationError("ledger contains unexpected SQL triggers")
        except (sqlite3.Error, ValidationError) as exc:
            if hasattr(self, "db"):
                self.db.close()
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError("policy revision ledger setup failed closed") from exc

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

    def close(self) -> None:
        self.db.close()

    def read(self, *, audience: str) -> int:
        if not isinstance(audience, str) or not _AUDIENCE.fullmatch(audience):
            raise ValidationError("invalid policy ledger audience")
        try:
            row = self.db.execute(
                "SELECT key_id,sequence,digest FROM policy_revisions WHERE audience=?",
                (audience,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ValidationError("policy sequence read failed closed") from exc
        if row is None:
            return 0
        return _check_stored_record(row)

    def compare_and_advance(
        self,
        *,
        key_id: str,
        audience: str,
        expected_previous: int,
        next_sequence: int,
        payload_sha256: str,
    ) -> int:
        """Advance one revision only when the caller's observed floor is current.

        This prevents *DB-only* concurrent stale commits. It does NOT prove
        that a signature was verified, or make a firewall apply atomic with DB.
        """
        _check_id(key_id, audience)
        _check_seq(expected_previous)
        _check_seq(next_sequence)
        if (next_sequence <= expected_previous
                or not isinstance(payload_sha256, str)
                or not _HEX.fullmatch(payload_sha256)):
            raise ValidationError("invalid policy digest or nonincreasing revision")
        # Never roll back a transaction owned by a caller who shares this
        # connection. SQLite rejects nested BEGIN, but our exception handler
        # otherwise could ROLLBACK the caller's unrelated uncommitted work.
        if self.db.in_transaction:
            raise ValidationError("policy revision ledger requires idle connection")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT key_id,sequence,digest FROM policy_revisions WHERE audience=?",
                (audience,),
            ).fetchone()
            current = 0 if row is None else _check_stored_record(row)
            if current != expected_previous:
                raise ValidationError("stale or conflicting local policy revision")
            if row is None:
                self.db.execute(
                    "INSERT INTO policy_revisions(audience,key_id,sequence,digest)"
                    " VALUES (?,?,?,?)",
                    (audience, key_id, next_sequence, payload_sha256),
                )
            else:
                result = self.db.execute(
                    "UPDATE policy_revisions SET key_id=?,sequence=?,digest=?"
                    " WHERE audience=? AND sequence=?",
                    (key_id, next_sequence, payload_sha256, audience, current),
                )
                if result.rowcount != 1:
                    raise ValidationError("concurrent policy revision changed")
            self.db.execute("COMMIT")
            return next_sequence
        except (sqlite3.Error, ValidationError) as exc:
            if self.db.in_transaction:
                try:
                    self.db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError("policy revision transaction failed closed") from exc

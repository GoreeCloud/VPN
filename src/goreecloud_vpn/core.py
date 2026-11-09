"""Local-first management state. Does NOT enforce traffic or create VPN tunnels."""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
from uuid import uuid4

LABEL = re.compile(r"^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$")
GROUP = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ENDPOINT = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})$")
RFC1918 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
))


class ValidationError(ValueError):
    """Untrusted management input is invalid."""


def check_label(value):
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise ValidationError("invalid DNS-safe name")
    return value


def check_group(value):
    if not isinstance(value, str) or not GROUP.fullmatch(value):
        raise ValidationError("invalid group")
    return value


def check_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValidationError("expected a WireGuard public key")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("invalid WireGuard public key") from exc
    if len(data) != 32 or data == bytes(32):
        raise ValidationError("invalid WireGuard public key")
    # Reject alternate base64 spellings of the same 32-byte key. Non-zero
    # padding bits otherwise bypass the unique-key and revocation tombstone.
    if base64.b64encode(data).decode("ascii") != value:
        raise ValidationError("noncanonical WireGuard public key")
    return value


def check_endpoint(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 254:
        raise ValidationError("invalid endpoint")
    m = ENDPOINT.fullmatch(value)
    if not m or not 1 <= int(m.group(2)) <= 65535:
        raise ValidationError("invalid endpoint: expected host:port or [IPv6]:port")
    if m.group(1).startswith("["):
        try:
            ipaddress.IPv6Address(m.group(1)[1:-1])
        except ValueError as exc:
            raise ValidationError("invalid IPv6 endpoint") from exc
    return value


def _prepare_private_database(path: Path) -> tuple[int, int]:
    """Fail closed on unsafe existing SQLite files without chmod or following links.

    This is a local-owner preflight, not protection against a compromised
    account or a privileged process replacing the file after it is opened.
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise ValidationError("secure local database opening unavailable")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = os.stat(path.parent, follow_symlinks=False)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise ValidationError("database directory must be owner-only")
        read_flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                      | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(path, read_flags)
        except FileNotFoundError:
            # Exclusive creation prevents a second actor from racing a
            # missing file into a symlink or foreign-owned inode.
            fd = os.open(
                path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), 0o600
            )
        try:
            info = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ValidationError("database file must be owner-only")
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)
    except OSError:
        raise ValidationError("unsafe database storage path") from None


class VPNStore:
    """SQLite records for peer identities, policies and private address allocation."""

    def __init__(self, path, subnet="10.234.12.0/24", domain="vpn.internal"):
        try:
            self.network = ipaddress.ip_network(subnet, strict=True)
        except ValueError as exc:
            raise ValidationError("invalid subnet") from exc
        if (self.network.version != 4 or not any(self.network.subnet_of(r) for r in RFC1918)
                or not 16 <= self.network.num_addresses <= 65536):
            raise ValidationError("subnet must be RFC1918 private IPv4 with 16 to 65536 addresses")
        if not isinstance(domain, str) or len(domain) > 253 or any(
            not LABEL.fullmatch(label) for label in domain.split(".")
        ):
            raise ValidationError("invalid domain")
        self.domain = domain
        path = Path(path).expanduser()
        identity = _prepare_private_database(path)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=5)
        try:
            opened = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                    or opened.st_nlink != 1 or opened.st_mode & 0o077
                    or (opened.st_dev, opened.st_ino) != identity):
                raise ValidationError("database identity changed before initialization")
        except (OSError, ValidationError):
            self.db.close()
            raise ValidationError("unsafe database storage path") from None
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS peers (
                id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                public_key TEXT UNIQUE NOT NULL, address TEXT UNIQUE NOT NULL,
                endpoint TEXT, groups TEXT NOT NULL, created TEXT NOT NULL
            )""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                protocol TEXT NOT NULL, ports TEXT NOT NULL, created TEXT NOT NULL
            )""")
            # Fail closed when upgrading pre-approval alpha databases.
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(peers)")}
            if "status" not in columns:
                self.db.execute(
                    "ALTER TABLE peers ADD COLUMN status TEXT NOT NULL DEFAULT 'pending' "
                    "CHECK(status IN ('pending','approved','revoked'))"
                )
            self.db.execute("""CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL, peer_id TEXT NOT NULL, recorded TEXT NOT NULL
            )""")

    @staticmethod
    def _peer(row):
        result = dict(row)
        result["groups"] = json.loads(result["groups"])
        return result

    @staticmethod
    def _policy(row):
        result = dict(row)
        result["ports"] = json.loads(result["ports"])
        result["action"] = "allow"
        return result

    def peers(self):
        with self.lock:
            return [self._peer(row) for row in self.db.execute("SELECT * FROM peers ORDER BY name")]

    def policies(self):
        with self.lock:
            return [self._policy(row) for row in self.db.execute("SELECT * FROM policies ORDER BY created,id")]

    def add_peer(self, name, public_key, groups, endpoint=None):
        name, public_key, endpoint = check_label(name), check_key(public_key), check_endpoint(endpoint)
        if not isinstance(groups, list) or len(groups) > 32:
            raise ValidationError("groups must be an array of at most 32 names")
        groups = sorted({check_group(group) for group in groups})
        with self.lock, self.db:
            used = {row[0] for row in self.db.execute("SELECT address FROM peers")}
            address = next((str(ipaddress.ip_address(int(self.network.network_address) + i))
                            for i in range(10, self.network.num_addresses - 1)
                            if str(ipaddress.ip_address(int(self.network.network_address) + i)) not in used), None)
            if address is None:
                raise ValidationError("address pool exhausted")
            record = (str(uuid4()), name, public_key, address, endpoint, json.dumps(groups),
                      datetime.now(timezone.utc).isoformat())
            try:
                self.db.execute(
                    "INSERT INTO peers (id,name,public_key,address,endpoint,groups,created,status)"
                    " VALUES (?,?,?,?,?,?,?,'pending')", record
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationError("duplicate peer name or public key") from exc
            self._event("peer_registered", record[0])
            return self._peer(self.db.execute("SELECT * FROM peers WHERE id=?", (record[0],)).fetchone())

    def _event(self, kind, peer_id):
        self.db.execute(
            "INSERT INTO events (kind,peer_id,recorded) VALUES (?,?,?)",
            (kind, peer_id, datetime.now(timezone.utc).isoformat())
        )

    def events(self):
        return self.event_page()["events"]

    def event_page(self, limit=200, before=None, peer_id=None, kind=None):
        """Newest-first keyset pagination; retained local history is not tamper-proof."""
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValidationError("limit must be an integer from 1 to 200")
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63 - 1):
            raise ValidationError("before must be a positive SQLite sequence number")
        if peer_id is not None and (not isinstance(peer_id, str) or not 1 <= len(peer_id) <= 128):
            raise ValidationError("invalid peer identity filter")
        if kind is not None and kind not in ("peer_registered", "peer_approved", "peer_revoked"):
            raise ValidationError("invalid event kind")
        clauses, values = [], []
        for column, operator, value in (("seq", "<", before), ("peer_id", "=", peer_id), ("kind", "=", kind)):
            if value is not None:
                clauses.append(column + operator + "?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.lock:
            rows = [dict(row) for row in self.db.execute(
                "SELECT * FROM events" + where + " ORDER BY seq DESC LIMIT ?", values + [limit + 1]
            )]
        events = rows[:limit]
        return {"events": events, "next_before": events[-1]["seq"] if len(rows) > limit else None,
                "tamper_proof": False}

    def approve_peer(self, peer_id):
        if not isinstance(peer_id, str):
            raise ValidationError("invalid peer identity")
        with self.lock, self.db:
            count = self.db.execute(
                "UPDATE peers SET status='approved' WHERE id=? AND status='pending'",
                (peer_id,)
            ).rowcount
            if count:
                self._event("peer_approved", peer_id)
            return count == 1

    def revoke_peer(self, peer_id):
        if not isinstance(peer_id, str):
            raise ValidationError("invalid peer identity")
        with self.lock, self.db:
            count = self.db.execute(
                "UPDATE peers SET status='revoked' WHERE id=? AND status IN ('pending','approved')",
                (peer_id,)
            ).rowcount
            if count:
                self._event("peer_revoked", peer_id)
            return count == 1

    def delete_peer(self, peer_id):
        # Logical removal preserves a tombstone to prevent revoked key reuse.
        return self.revoke_peer(peer_id)

    def add_policy(self, source, target, protocol, ports):
        source, target = check_group(source), check_group(target)
        if protocol not in ("tcp", "udp", "icmp"):
            raise ValidationError("unsupported protocol")
        if not isinstance(ports, list) or len(ports) > 64 or any(
            type(x) is not int or not 1 <= x <= 65535 for x in ports
        ):
            raise ValidationError("invalid ports")
        if (protocol == "icmp" and ports) or (protocol != "icmp" and not ports):
            raise ValidationError("TCP/UDP require ports and ICMP forbids ports")
        record = (str(uuid4()), source, target, protocol, json.dumps(sorted(set(ports))),
                  datetime.now(timezone.utc).isoformat())
        with self.lock, self.db:
            self.db.execute("INSERT INTO policies VALUES (?,?,?,?,?,?)", record)
            return self._policy(self.db.execute("SELECT * FROM policies WHERE id=?", (record[0],)).fetchone())

    def delete_policy(self, rule_id):
        with self.lock, self.db:
            return self.db.execute("DELETE FROM policies WHERE id=?", (rule_id,)).rowcount == 1

    def snapshot(self):
        """Read peers and policies together, serialized with this store's writers."""
        with self.lock:
            return self.peers(), self.policies()

    def explain_access(self, source_id, target_id, protocol, port=None):
        from .diagnostics import evaluate_access
        peers, policies = self.snapshot()
        return evaluate_access(peers, policies, source_id, target_id, protocol, port)

    def allowed(self, source_id, target_id, protocol, port=None):
        return self.explain_access(source_id, target_id, protocol, port)["allowed"]

    def dns_records(self):
        return [{"name": p["name"] + "." + self.domain, "type": "A", "address": p["address"]}
                for p in self.peers() if p["status"] == "approved"]

    def close(self):
        with self.lock:
            self.db.close()

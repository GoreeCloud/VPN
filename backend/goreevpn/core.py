"""Validation, private SQLite inventory, and offline WireGuard server rendering."""
import base64
from contextlib import contextmanager
import binascii
import ipaddress
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
import uuid

NETWORK = ipaddress.ip_network("10.77.0.0/24")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}\Z")


class InvalidInput(ValueError):
    pass


class Conflict(ValueError):
    pass


def valid_public_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise InvalidInput("WireGuard public key must be a canonical 32-byte base64 key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidInput("Invalid WireGuard public key") from None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise InvalidInput("Invalid WireGuard public key")
    return value


def valid_name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise InvalidInput("Name must be 1–64 safe characters, beginning with a letter or digit")
    return value


def secure_private_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InvalidInput("Key file must be a regular, non-symlink file")
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InvalidInput("Key file must be private (chmod 600)")
    return path


class Store:
    """Small local control-plane inventory, not an active WireGuard interface."""

    def __init__(self, path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.path.is_symlink():
            raise InvalidInput("Database must not be a symlink")
        if self.path.exists() and not self.path.is_file():
            raise InvalidInput("Database path must be a regular file")
        self._init()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self):
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS peers (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
                revoked_at INTEGER
            )""")
        os.chmod(self.path, 0o600)

    @staticmethod
    def _as_dict(row):
        return dict(row)

    def peers(self):
        with self._connect() as conn:
            return [self._as_dict(row) for row in conn.execute(
                "SELECT id,name,public_key,address,created_at,revoked_at "
                "FROM peers ORDER BY created_at, id"
            )]

    def enroll(self, name, public_key):
        valid_name(name)
        valid_public_key(public_key)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM peers WHERE public_key=?", (public_key,)).fetchone():
                raise Conflict("Public key has already been enrolled")
            used = {row["address"].split("/", 1)[0] for row in conn.execute("SELECT address FROM peers")}
            address = next((str(ip) for ip in list(NETWORK.hosts())[1:] if str(ip) not in used), None)
            if not address:
                raise Conflict("VPN address pool exhausted")
            record = {
                "id": uuid.uuid4().hex, "name": name, "public_key": public_key,
                "address": address + "/32", "created_at": int(time.time()),
                "revoked_at": None,
            }
            conn.execute(
                "INSERT INTO peers(id,name,public_key,address,created_at,revoked_at) "
                "VALUES (:id,:name,:public_key,:address,:created_at,:revoked_at)", record
            )
        return record

    def revoke(self, peer_id):
        if not isinstance(peer_id, str) or not re.fullmatch(r"[0-9a-f]{32}", peer_id):
            raise InvalidInput("Invalid peer identifier")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                "UPDATE peers SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                (int(time.time()), peer_id)
            ).rowcount
        return bool(changed)


def render_server(store, key_file, output, listen_port=51820):
    """Offline generation ONLY. Never invokes wg, networking, or elevated privileges."""
    if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
        raise InvalidInput("Invalid UDP listen port")
    secret = secure_private_file(key_file).read_text(encoding="ascii").strip()
    valid_public_key(secret)  # WireGuard private keys share canonical 32-byte encoding.
    output = Path(output)
    if output.is_symlink():
        raise InvalidInput("Output must not be a symlink")
    if not output.parent.is_dir():
        raise InvalidInput("Output directory does not exist")
    lines = ["# Generated by GoreeCloud VPN. Contains a PRIVATE KEY; protect this file.",
             "[Interface]", "Address = 10.77.0.1/24",
             "ListenPort = " + str(listen_port), "PrivateKey = " + secret]
    for peer in store.peers():
        if peer["revoked_at"] is None:
            lines.extend(["", "[Peer]", "# " + peer["id"],
                          "PublicKey = " + peer["public_key"],
                          "AllowedIPs = " + peer["address"]])
    content = "\n".join(lines) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".gcvpn-", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, output)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return len(store.peers())

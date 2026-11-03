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
import threading
from uuid import uuid4

LABEL = re.compile(r"^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$")
GROUP = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ENDPOINT = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})$")


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


class VPNStore:
    """SQLite records for peer identities, policies and private address allocation."""

    def __init__(self, path, subnet="10.234.12.0/24", domain="vpn.internal"):
        try:
            self.network = ipaddress.ip_network(subnet, strict=True)
        except ValueError as exc:
            raise ValidationError("invalid subnet") from exc
        if (self.network.version != 4 or not self.network.is_private
                or not 16 <= self.network.num_addresses <= 65536):
            raise ValidationError("subnet must be private IPv4 with 16 to 65536 addresses")
        if not isinstance(domain, str) or len(domain) > 253 or any(
            not LABEL.fullmatch(label) for label in domain.split(".")
        ):
            raise ValidationError("invalid domain")
        self.domain = domain
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValidationError("database path cannot be a symlink")
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=5)
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
                self.db.execute("INSERT INTO peers VALUES (?,?,?,?,?,?,?)", record)
            except sqlite3.IntegrityError as exc:
                raise ValidationError("duplicate peer name or public key") from exc
            return self._peer(self.db.execute("SELECT * FROM peers WHERE id=?", (record[0],)).fetchone())

    def delete_peer(self, peer_id):
        with self.lock, self.db:
            return self.db.execute("DELETE FROM peers WHERE id=?", (peer_id,)).rowcount == 1

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

    def allowed(self, source_id, target_id, protocol, port=None):
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            raise ValidationError("invalid peer identity")
        if protocol not in ("tcp", "udp", "icmp"):
            raise ValidationError("invalid protocol")
        if (protocol == "icmp" and port is not None) or (protocol != "icmp" and (
            type(port) is not int or not 1 <= port <= 65535
        )):
            raise ValidationError("invalid port for protocol")
        with self.lock:
            src = self.db.execute("SELECT groups FROM peers WHERE id=?", (source_id,)).fetchone()
            dst = self.db.execute("SELECT groups FROM peers WHERE id=?", (target_id,)).fetchone()
            if not src or not dst or source_id == target_id:
                return False
            src_groups, dst_groups = set(json.loads(src["groups"])), set(json.loads(dst["groups"]))
            for rule in self.db.execute("SELECT * FROM policies WHERE protocol=?", (protocol,)):
                if rule["source"] in src_groups and rule["target"] in dst_groups:
                    if protocol == "icmp" or port in json.loads(rule["ports"]):
                        return True
            return False

    def dns_records(self):
        return [{"name": p["name"] + "." + self.domain, "type": "A", "address": p["address"]}
                for p in self.peers()]

    def close(self):
        with self.lock:
            self.db.close()

#!/usr/bin/env python3
"""GoreeCloud NetBird CLI: bounded, audited REST administration for VPS Mesh.

Python 3 standard library. Requests only the verified NetBird HTTPS origin.
Dry runs do not require a token and never contact the network.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import sys
import urllib.error
import urllib.request

BASE = "https://netbird.goreecloud.com"
CONFIG = Path.home() / ".config/goreecloud/netbird-cli"
TOKEN_FILE = CONFIG / "pat"
MAX_INPUT = 512 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
WRITE_METHODS = {"POST", "PUT", "DELETE"}
ID = r"[A-Za-z0-9_-]{1,96}"
COLLECTIONS = {
    "peers": ("peers", {"GET", "PUT", "DELETE"}),
    "groups": ("groups", {"GET", "POST", "PUT", "DELETE"}),
    "policies": ("policies", {"GET", "POST", "PUT", "DELETE"}),
    "setup-keys": ("setup-keys", {"GET", "POST", "PUT", "DELETE"}),
    "users": ("users", {"GET", "POST", "PUT", "DELETE"}),
    "networks": ("networks", {"GET", "POST", "PUT", "DELETE"}),
    "routes": ("routes", {"GET", "POST", "PUT", "DELETE"}),
    "posture-checks": ("posture-checks", {"GET", "POST", "PUT", "DELETE"}),
    "dns-zones": ("dns/zones", {"GET", "POST", "PUT", "DELETE"}),
    "dns-nameservers": ("dns/nameservers", {"GET", "POST", "PUT", "DELETE"}),
    "dns-settings": ("dns/settings", {"GET", "PUT"}),
    "events-audit": ("events/audit", {"GET"}),
    "events-traffic": ("events/network-traffic", {"GET"}),
}
NO_DATA_KEYS = frozenset(("key", "secret", "password", "token", "access_token",
                          "refresh_token", "personal_access_token", "setup_key",
                          "authorization", "cookie", "private_key", "hash"))
SUMMARY_KEYS = ("id", "name", "hostname", "ip", "connected", "enabled", "role",
                "description", "issued", "domain", "type", "status", "expires",
                "expires_at", "peers_count", "resources_count", "groups",
                "peer_groups", "protocol", "port", "metric", "network",
                "distribution_groups", "rules")
LOCAL_DB = Path.home() / "goreecloud-netbird-fresh/data/store.db"
PATH_RE = re.compile(
    r"^/api/(?:"
    + r"(?:peers|groups|policies|setup-keys|users|routes|posture-checks)"
    + rf"(?:/{ID})?"
    + r"|networks"
    + rf"(?:/{ID}(?:/(?:resources|routers)(?:/{ID})?)?)?"
    + r"|dns/(?:zones"
    + rf"(?:/{ID}(?:/records(?:/{ID})?)?)?"
    + rf"|nameservers(?:/{ID})?"
    + r"|settings)"
    + r"|events/(?:audit|network-traffic)"
    + r")$"
)

class CLIError(Exception):
    """Non-sensitive CLI error for the terminal."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise CLIError("HTTP redirect refused; refusing to forward credential")


def secure_dir():
    CONFIG.mkdir(mode=0o700, parents=True, exist_ok=True)
    if CONFIG.is_symlink() or stat.S_IMODE(CONFIG.stat().st_mode) & 0o077:
        raise CLIError("CLI configuration directory must be a private, real 0700 directory")


def read_pat():
    try:
        s = TOKEN_FILE.lstat()
    except FileNotFoundError:
        raise CLIError("No PAT enrolled. Use 'gc-netbird login' in your private VPS terminal")
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != os.getuid():
        raise CLIError("PAT file must be owned by this user, regular and mode 0600")
    token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not token or len(token) > 2048 or any(c.isspace() for c in token):
        raise CLIError("PAT file is invalid; replace it privately")
    return token


def private_save(path, content):
    dst = Path(path).expanduser()
    if dst.is_symlink() or dst.exists():
        raise CLIError("Refusing to overwrite an existing output path")
    if not dst.parent.is_dir() or dst.parent.is_symlink():
        raise CLIError("Output parent directory must exist and be real")
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(dst, 0o600)


def valid_path(path, method):
    if not isinstance(path, str) or len(path) > 350 or not PATH_RE.fullmatch(path):
        raise CLIError("Unsupported API path; only documented NetBird resource paths are allowed")
    if method not in ("GET", "POST", "PUT", "DELETE"):
        raise CLIError("Unsupported HTTP method")
    if path.startswith("/api/events/") and method != "GET":
        raise CLIError("Audit events are read-only")
    parts = path.split("/")
    if method in ("DELETE", "PUT") and path != "/api/dns/settings":
        if parts[-1] in ("peers", "groups", "policies", "setup-keys", "users", "routes",
                         "networks", "posture-checks", "zones", "nameservers",
                         "records", "resources", "routers") or len(parts) < 4:
            raise CLIError("PUT/DELETE requires a concrete resource ID")
    if method == "POST":
        base_names = {"/api/" + path for path, methods in COLLECTIONS.values() if "POST" in methods}
        nested_names = bool(re.fullmatch(r"/api/networks/" + ID + r"/(?:resources|routers)", path) or
                            re.fullmatch(r"/api/dns/zones/" + ID + r"/records", path))
        if path not in base_names and not nested_names:
            raise CLIError("POST requires a documented resource collection")
    if method == "POST" and path.endswith("/settings"):
        raise CLIError("DNS settings use PUT, not POST")
    return path


def resource_path(name, resource_id=None):
    if name not in COLLECTIONS:
        raise CLIError("Unsupported resource. Run 'gc-netbird resources'")
    path = "/api/" + COLLECTIONS[name][0]
    if resource_id is not None:
        if name in ("dns-settings", "events-audit", "events-traffic"):
            raise CLIError("This resource has no item ID")
        if not re.fullmatch(ID, resource_id):
            raise CLIError("Resource ID must be a plain NetBird identifier")
        path += "/" + resource_id
    return path


def load_payload(filename):
    file = Path(filename).expanduser()
    if file.is_symlink() or not file.is_file():
        raise CLIError("Input JSON must be a regular, non-symlink file")
    if file.stat().st_mode & 0o022:
        raise CLIError("Input JSON may not be writable by group or other users")
    if file.stat().st_size > MAX_INPUT:
        raise CLIError("Input JSON too large")
    try:
        raw = file.read_bytes()
        if len(raw) > MAX_INPUT:
            raise CLIError("Input JSON too large")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise CLIError("Write body must be a JSON object")
        result = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(result) > MAX_INPUT:
            raise CLIError("Write body too large")
        return value, result
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CLIError("Invalid JSON body") from exc


def validate_payload(method, path, obj):
    if method in ("GET", "DELETE"):
        if obj is not None:
            raise CLIError("GET and DELETE do not accept a JSON body")
        return
    if not isinstance(obj, dict) or not obj:
        raise CLIError("POST/PUT requires a nonempty JSON object via --data-file")
    root = path.split("/")[2]
    if root in ("groups", "policies") or path == "/api/dns/zones":
        name = obj.get("name")
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 255):
            raise CLIError("Group, policy, or DNS zone requires a nonempty name")
    if root == "policies":
        rules = obj.get("rules")
        if not isinstance(rules, list) or not rules:
            raise CLIError("Policy writes require a nonempty rules array")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("sources"), list) or not isinstance(rule.get("destinations"), list):
                raise CLIError("Every policy rule needs sources and destinations arrays")
            if not rule["sources"] or not rule["destinations"]:
                raise CLIError("Policy rules may not have empty sources or destinations")
    if path.endswith("/records") or "/records/" in path:
        if obj.get("type") not in ("A", "AAAA", "CNAME", "TXT", "SRV"):
            raise CLIError("DNS record requires a supported record type")
        if not isinstance(obj.get("name"), str) or not obj["name"].strip():
            raise CLIError("DNS record requires a name")
        if not isinstance(obj.get("content"), str) or not obj["content"].strip():
            raise CLIError("DNS record requires content")
    if path.startswith("/api/dns/zones") and (path == "/api/dns/zones" or path.count("/") == 4):
        if not isinstance(obj.get("domain"), str) or not obj["domain"].strip():
            raise CLIError("DNS zone requires a domain")
        if not isinstance(obj.get("distribution_groups"), list):
            raise CLIError("DNS zone requires distribution_groups array")
        if obj.get("enable_search_domain") not in (True, False):
            raise CLIError("DNS zone requires enable_search_domain boolean")


def safe_tree(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in NO_DATA_KEYS else safe_tree(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [safe_tree(item) for item in value]
    return value


def compact_item(value):
    if not isinstance(value, dict):
        return safe_tree(value)
    result = {}
    for k in SUMMARY_KEYS:
        if k not in value:
            continue
        v = value[k]
        if k == "rules" and isinstance(v, list):
            result["rule_count"] = len(v)
        elif k in ("groups", "peer_groups", "distribution_groups") and isinstance(v, list):
            result[k] = [x if isinstance(x, str) else (x.get("id") or x.get("name")) for x in v][:50]
        else:
            result[k] = safe_tree(v)
    return result


def display_result(value, show_data=False):
    if show_data:
        display = safe_tree(value)
    elif isinstance(value, list):
        display = {"count": len(value), "items": [compact_item(item) for item in value[:250]]}
        if len(value) > 250:
            display["truncated"] = True
    elif isinstance(value, dict):
        display = compact_item(value)
    else:
        display = safe_tree(value)
    print(json.dumps(display, indent=2, ensure_ascii=False))


class NetBirdClient:
    def __init__(self, opener=None, base=BASE):
        if not base.startswith("https://") and opener is None:
            raise CLIError("TLS required for the NetBird API")
        self.base = base
        self.opener = opener if opener is not None else urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def request(self, method, path, token, body=None):
        valid_path(path, method)
        req = urllib.request.Request(
            self.base + path, method=method, data=body,
            headers={"Authorization": "Token " + token,
                     "Accept": "application/json",
                     "Content-Type": "application/json",
                     "User-Agent": "GoreeCloud-NetBird-CLI/1.0"}
        )
        try:
            with self.opener.open(req, timeout=12) as resp:
                if resp.geturl() != self.base + path:
                    raise CLIError("Untrusted API redirect")
                raw = resp.read(MAX_OUTPUT + 1)
                if len(raw) > MAX_OUTPUT:
                    raise CLIError("API response too large; use narrower requests")
                if not raw:
                    return resp.status, None
                try:
                    return resp.status, json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise CLIError("API returned a non-JSON body")
        except urllib.error.HTTPError as exc:
            raise CLIError(f"NetBird API returned HTTP {exc.code} for {method} {path}") from None
        except urllib.error.URLError:
            raise CLIError("NetBird API connection failed; verify HTTPS and service status") from None


def command_action(args):
    if args.operation == "api":
        method, path = args.method, args.path
        resource = path.split("/")[2]
    else:
        resource = args.resource
        if args.operation == "list":
            method, path = "GET", resource_path(resource)
        elif args.operation == "get":
            method, path = "GET", resource_path(resource, args.id)
        elif args.operation == "create":
            method, path = "POST", resource_path(resource)
        elif args.operation == "update":
            method, path = "PUT", resource_path(resource, args.id)
        elif args.operation == "delete":
            method, path = "DELETE", resource_path(resource, args.id)
        else:
            raise CLIError("Unsupported action")
        if method not in COLLECTIONS[resource][1]:
            raise CLIError(f"{resource} does not support {method}")
    valid_path(path, method)
    data = None
    obj = None
    if args.data_file:
        obj, data = load_payload(args.data_file)
    validate_payload(method, path, obj)
    if args.dry_run:
        digest = hashlib.sha256(data).hexdigest()[:16] if data is not None else None
        print(json.dumps({"dry_run": True, "network_sent": False, "method": method,
                          "path": path, "body_sha256_prefix": digest,
                          "body_fields": sorted(obj) if obj is not None else []}, indent=2))
        return 0
    write = method in WRITE_METHODS
    if write:
        # Public examples are intentionally non-deployable until reviewed IDs
        # and private overlay addresses replace every placeholder.
        if "REPLACE_" in path or (obj is not None and "REPLACE_" in json.dumps(obj)):
            raise CLIError("Unresolved example placeholder; verify live IDs and private IP before a network write")
        if not args.confirm_write or not args.confirm_network_impact:
            raise CLIError("Live writes require --confirm-write AND --confirm-network-impact")
        if method == "DELETE" and not args.confirm_delete:
            raise CLIError("Deletes additionally require --confirm-delete")
        if path == "/api/setup-keys" and method == "POST" and not args.output:
            raise CLIError("Setup-key creation requires --output to a private new file")
    token = read_pat()
    status, result = NetBirdClient().request(method, path, token, data)
    if args.output:
        private_save(args.output, json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(f"HTTP {status}; response stored privately (0600), no overwrite")
    elif write:
        item_id = result.get("id", "") if isinstance(result, dict) else ""
        print(f"HTTP {status}; {method} {path} completed" + (f"; resource id {item_id}" if item_id else ""))
        if path == "/api/setup-keys":
            print("Sensitive key values are never printed")
    else:
        display_result(result, args.show_data)
    return 0


def command_login():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise CLIError("Login requires a private interactive TTY on VPS Mesh")
    secure_dir()
    if TOKEN_FILE.exists() or TOKEN_FILE.is_symlink():
        raise CLIError("A PAT is already enrolled. Revoke/rotate and logout first")
    token = getpass.getpass("NetBird personal access token (hidden): ")
    if not token or any(c.isspace() for c in token) or len(token) > 2048:
        raise CLIError("Invalid PAT input")
    NetBirdClient().request("GET", "/api/peers", token)
    private_save(TOKEN_FILE, token + "\n")
    print("PAT verified with authenticated GET /api/peers and stored locally (0600)")
    return 0


def command_logout(args):
    if not args.confirm_write:
        raise CLIError("Local logout requires --confirm-write (does not revoke token server-side)")
    if not TOKEN_FILE.exists():
        raise CLIError("No locally stored PAT")
    read_pat()
    TOKEN_FILE.unlink()
    print("Local PAT file removed; revoke this PAT in NetBird dashboard separately")
    return 0


def local_list(name):
    """Emergency read-only count/list from *fresh* VPS SQLite. API stays authoritative."""
    fields = {
        "peers": ("peers", "id,name,ip,meta_hostname"),
        "groups": ("groups", "id,name"),
        "policies": ("policies", "id,name,enabled"),
    }
    if name not in fields:
        raise CLIError("local-list permits only peers, groups or policies")
    p = LOCAL_DB
    if p.is_symlink() or not p.is_file() or not p.parent.is_dir():
        raise CLIError("Fresh VPS NetBird state unavailable")
    if stat.S_IMODE(p.parent.stat().st_mode) & 0o077:
        raise CLIError("Fresh NetBird data directory must be private")
    table, columns = fields[name]
    try:
        with sqlite3.connect("file:" + str(p) + "?mode=ro", uri=True, timeout=3) as db:
            db.execute("PRAGMA query_only=ON")
            cursor = db.execute("SELECT " + columns + " FROM " + table + " LIMIT 251")
            names = [c[0] for c in cursor.description]
            records = [dict(zip(names, row)) for row in cursor.fetchall()]
        print(json.dumps({"source": "fresh local SQLite read-only; API preferred",
                          "resource": name, "count_returned": min(len(records), 250),
                          "truncated": len(records) > 250, "items": records[:250]},
                         indent=2, ensure_ascii=False))
    except (sqlite3.Error, ValueError) as exc:
        raise CLIError("Local NetBird database read failed") from exc
    return 0


def doctor():
    try:
        urllib.request.urlopen(urllib.request.Request(BASE + "/api/instance",
                                                      headers={"Accept": "application/json"}), timeout=8).close()
        print("NetBird HTTPS public instance endpoint: reachable")
    except Exception:
        print("NetBird HTTPS public instance endpoint: unavailable")
    try:
        read_pat()
        print("API credential: enrolled (contents hidden)")
    except CLIError:
        print("API credential: not enrolled")
    print("Backend: " + BASE)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gc-netbird",
        description="Read and manage NetBird safely via the authorized VPS")
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("resources", help="Show supported resource names")
    sub.add_parser("doctor", help="Public service health and private token presence")
    sub.add_parser("login", help="Enroll PAT via hidden input with live API verification")
    logout = sub.add_parser("logout", help="Delete local PAT only")
    logout.add_argument("--confirm-write", action="store_true")
    sub.add_parser("auth-check", help="Verify authenticated peer-list access")
    loc = sub.add_parser("local-list", help="Read nonsecret peers/groups/policies from fresh VPS SQLite, no PAT")
    loc.add_argument("resource", choices=("peers", "groups", "policies"))
    for action in ("list", "get", "create", "update", "delete"):
        p = sub.add_parser(action)
        p.add_argument("resource", choices=tuple(COLLECTIONS))
        if action in ("get", "update", "delete"):
            p.add_argument("id")
        add_options(p)
    api = sub.add_parser("api", help="Allowlisted REST path for nested resources and newer APIs")
    api.add_argument("method", choices=("GET", "POST", "PUT", "DELETE"))
    api.add_argument("path", help="Fixed /api/... path, not arbitrary URLs or queries")
    add_options(api)
    args = parser.parse_args(argv)
    try:
        if args.operation == "resources":
            for name, (path, methods) in COLLECTIONS.items():
                print(f"{name:18} /api/{path:24} {','.join(sorted(methods))}")
            return 0
        if args.operation == "doctor":
            doctor()
            return 0
        if args.operation == "local-list":
            return local_list(args.resource)
        if args.operation == "login":
            return command_login()
        if args.operation == "logout":
            return command_logout(args)
        if args.operation == "auth-check":
            count = NetBirdClient().request("GET", "/api/peers", read_pat())[1]
            print("Authenticated NetBird API GET /api/peers passed; " +
                  str(len(count) if isinstance(count, list) else "unknown") + " peer(s)")
            return 0
        return command_action(args)
    except (CLIError, OSError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


def add_options(parser):
    parser.add_argument("--data-file", help="Local JSON object, not pasted on command line")
    parser.add_argument("--dry-run", action="store_true", help="Validate offline; no network and no PAT needed")
    parser.add_argument("--confirm-write", action="store_true", help="Authorize HTTP mutation")
    parser.add_argument("--confirm-network-impact", action="store_true", help="Acknowledge policy/routing/DNS impact")
    parser.add_argument("--confirm-delete", action="store_true", help="Extra gate for destructive delete")
    parser.add_argument("--show-data", action="store_true", help="Show full redacted JSON")
    parser.add_argument("--output", help="Save complete raw response privately mode 0600, no overwrite")


if __name__ == "__main__":
    sys.exit(main())

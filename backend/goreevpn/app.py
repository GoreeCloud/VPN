"""Loopback-only, bearer-protected JSON management API. No tunnel side effects."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

from .core import Conflict, InvalidInput, Store

HEALTH = {"status": "ok", "maturity": "alpha", "component": "management"}


def create_handler(store, token, allowed_hosts=("127.0.0.1", "localhost")):
    if not isinstance(token, str) or len(token) < 32 or token.strip() != token:
        raise ValueError("GCVPN_ADMIN_TOKEN must be at least 32 characters")
    hosts = frozenset(allowed_hosts)

    class Handler(BaseHTTPRequestHandler):
        server_version = "GoreeCloudVPN"
        sys_version = ""

        def log_message(self, *_args):
            # No client IPs, URLs, keys or tokens in default application logs.
            pass

        def _reply(self, status, payload):
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _preflight(self):
            host = self.headers.get("Host", "").split(":", 1)[0].lower()
            if host not in hosts or not host:
                self._reply(400, {"error": "Invalid Host header"})
                return False
            if (self.headers.get_all("Host") or []).__len__() != 1:
                self._reply(400, {"error": "Ambiguous Host header"})
                return False
            if self.headers.get("Origin") or self.headers.get("Transfer-Encoding"):
                self._reply(403, {"error": "Browser-origin and chunked requests are not supported"})
                return False
            if "?" in self.path or "#" in self.path or urlsplit(self.path).path != self.path:
                self._reply(400, {"error": "Invalid request path"})
                return False
            return True

        def _auth(self):
            authorization = self.headers.get("Authorization", "")
            supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
            if len(supplied) > 4096 or not hmac.compare_digest(supplied, token):
                self._reply(401, {"error": "Unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self._preflight():
                return
            if self.path == "/healthz":
                return self._reply(200, HEALTH)
            if not self._auth():
                return
            if self.path == "/api/v1/peers":
                return self._reply(200, {"peers": store.peers()})
            if self.path == "/api/v1/readiness":
                return self._reply(200, {"management": "ready", "data_plane": "unverified"})
            return self._reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self._preflight() or not self._auth():
                return
            if self.path != "/api/v1/peers":
                return self._reply(404, {"error": "Not found"})
            lengths = self.headers.get_all("Content-Length") or []
            if (len(lengths) != 1 or not lengths[0].isdigit() or
                    not (1 <= int(lengths[0]) <= 4096)):
                return self._reply(400, {"error": "Invalid body size"})
            if self.headers.get("Content-Type", "").lower() != "application/json":
                return self._reply(415, {"error": "Expected application/json"})
            try:
                value = json.loads(self.rfile.read(int(lengths[0])))
                if not isinstance(value, dict) or set(value) != {"name", "public_key"}:
                    raise InvalidInput("Expected name and public_key only")
                peer = store.enroll(value["name"], value["public_key"])
                return self._reply(201, {"peer": peer})
            except Conflict as exc:
                return self._reply(409, {"error": str(exc)})
            except (ValueError, UnicodeError, InvalidInput) as exc:
                return self._reply(400, {"error": str(exc)[:160]})

        def do_DELETE(self):
            if not self._preflight() or not self._auth():
                return
            match = re.fullmatch(r"/api/v1/peers/([0-9a-f]{32})", self.path)
            if not match:
                return self._reply(404, {"error": "Not found"})
            try:
                changed = store.revoke(match.group(1))
            except InvalidInput:
                changed = False
            return self._reply(200 if changed else 404, {
                "revoked": changed
            } if changed else {"error": "Peer not found or already revoked"})

        def do_PUT(self):
            return self._reply(405, {"error": "Method not allowed"})

        def do_PATCH(self):
            return self._reply(405, {"error": "Method not allowed"})

    return Handler


def serve():
    token = os.environ.get("GCVPN_ADMIN_TOKEN", "")
    path = os.environ.get("GCVPN_DB", os.path.expanduser("~/.local/state/goreevpn/peers.sqlite3"))
    host = os.environ.get("GCVPN_BIND", "127.0.0.1")
    port = int(os.environ.get("GCVPN_PORT", "8787"))
    # No direct public management binding. Use a reviewed local reverse proxy + TLS.
    if not ipaddress.ip_address(host).is_loopback:
        raise SystemExit("Management must bind to numeric loopback")
    if not (1 <= port <= 65535):
        raise SystemExit("Invalid port")
    allowed = {"localhost", "127.0.0.1", "[::1]"}
    handler = create_handler(Store(path), token, allowed)
    server = ThreadingHTTPServer((host, port), handler)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

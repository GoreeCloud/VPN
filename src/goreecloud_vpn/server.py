"""Authenticated, loopback-only management API. Not a live VPN data plane."""
from __future__ import annotations

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
import socket
import threading
from urllib.parse import parse_qs, urlsplit

from .core import VPNStore, ValidationError
from .plan import build_peer_plan
from .diagnostics import management_status, policy_diagnostics, simulate_access

LOG = logging.getLogger("goreecloud_vpn")
# Bounded post-parser management headers; Python HTTP parser's own limits
# still apply *before* this application-level check.
MAX_MANAGEMENT_HEADER_FIELDS = 64
MAX_MANAGEMENT_HEADER_BYTES = 8192
MAX_MANAGEMENT_TARGET_CHARS = 2048
MANAGEMENT_SOCKET_TIMEOUT_SECONDS = 5
MAX_MANAGEMENT_CONCURRENT_CONNECTIONS = 16


def _unique_json_object(pairs):
    """Reject ambiguous keys at every depth, including Unicode escape aliases."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate JSON field")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(_value):
    # Python's json.loads otherwise accepts NaN/Infinity despite JSON's grammar.
    raise ValidationError("nonstandard JSON constant")


class _BoundedManagementHTTPServer(ThreadingHTTPServer):
    """Reject excess loopback sockets before creating unbounded worker threads.

    This bounds concurrent handlers, not all kernel listen-backlog sockets or
    connection rates. It does not make this alpha API safe for public ingress.
    """

    def __init__(self, server_address, request_handler_class):
        self._worker_slots = threading.BoundedSemaphore(MAX_MANAGEMENT_CONCURRENT_CONNECTIONS)
        super().__init__(server_address, request_handler_class)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            # Protocol-independent fixed refusal. Do not parse, authenticate or
            # log raw request bytes when all slots are occupied.
            try:
                request.settimeout(0.2)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n"
                    b"Cache-Control: no-store\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class _IPv6ThreadingHTTPServer(_BoundedManagementHTTPServer):
    """Bind the IPv6 loopback with an IPv6 socket, never an IPv4 wildcard."""
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    server_version = "GoreeCloudVPN-alpha"

    def setup(self):
        super().setup()
        # Bounds idle or incomplete requests on the *loopback* management
        # socket; this is not a complete network-layer or parser limit.
        self.connection.settimeout(self.server.socket_timeout_seconds)

    def reply(self, status, body):
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def trusted_request(self):
        """Bound parsed metadata and reject browser/rebinding management calls.

        Checks run before authorization and before all state changes, including
        the unauthenticated health endpoint. Stdlib parser-level limits still
        operate before these application checks.
        """
        fields = list(self.headers.raw_items())
        metadata_bytes = sum(
            len(name.encode("latin-1", errors="replace")) +
            len(value.encode("latin-1", errors="replace")) + 4
            for name, value in fields
        )
        if (len(fields) > MAX_MANAGEMENT_HEADER_FIELDS
                or metadata_bytes > MAX_MANAGEMENT_HEADER_BYTES):
            self.close_connection = True
            self.reply(431, {"error": "management headers exceed limit"})
            return False
        if len(self.path) > MAX_MANAGEMENT_TARGET_CHARS:
            self.close_connection = True
            self.reply(414, {"error": "management request target exceeds limit"})
            return False
        bound_ip = ipaddress.ip_address(self.server.server_address[0])
        port = self.server.server_port
        expected_host = (f"[{bound_ip}]:{port}" if bound_ip.version == 6
                         else f"{bound_ip}:{port}")
        host_headers = self.headers.get_all("Host", [])
        if len(host_headers) != 1 or host_headers[0] != expected_host:
            self.reply(421, {"error": "unrecognized management host"})
            return False
        # This API does not serve any browser UI. Reject even same-origin
        # browser requests until a reviewed session/CSRF design exists.
        if self.headers.get_all("Origin", []):
            self.reply(403, {"error": "browser-origin requests are unsupported"})
            return False
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.reply(400, {"error": "invalid request target"})
            return False
        return True

    def bodyless_request(self):
        """Reject declared bodies and conflicting framing on GET and DELETE.

        Neither route family consumes a request body. Reject ambiguity before
        authentication or a possible SQLite mutation, never drain unknown data.
        """
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get_all("Transfer-Encoding", []) or len(lengths) > 1
                or (lengths and lengths[0] != "0")):
            self.close_connection = True
            self.reply(400, {"error": "request body is unsupported"})
            return False
        return True

    def authorized(self):
        # A proxy and an application must not disagree about which bearer
        # credential is authoritative. Reject duplicate Authorization fields.
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer ") or not hmac.compare_digest(
            values[0][7:].encode("utf-8"), self.server.admin_token.encode("utf-8")
        ):
            self.reply(401, {"error": "unauthorized"})
            return False
        return True

    def body(self):
        if self.headers.get_all("Transfer-Encoding", []):
            raise ValidationError("Transfer-Encoding is unsupported")
        lengths = self.headers.get_all("Content-Length", [])
        # A single strict decimal length prevents conflicting request framing.
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 5:
            raise ValidationError("one decimal Content-Length required")
        length = int(lengths[0])
        if length > 16384:
            raise ValidationError("body size limit exceeded")
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or self.headers.get_content_type() != "application/json":
            raise ValidationError("one application/json Content-Type required")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValidationError("incomplete JSON body")
            result = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_nonstandard_json_constant,
            )
        except ValidationError:
            raise
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("invalid JSON") from exc
        if not isinstance(result, dict):
            raise ValidationError("expected JSON object")
        return result

    def do_GET(self):
        if not self.trusted_request() or not self.bodyless_request():
            return
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.reply(200, {"status": "ok", "maturity": "alpha", "component": "management"})
            return
        if not self.authorized():
            return
        if path == "/api/v1/status":
            self.reply(200, management_status(self.server.store))
        elif path == "/api/v1/policies/diagnostics":
            self.reply(200, policy_diagnostics(self.server.store))
        elif path == "/api/v1/peers":
            self.reply(200, {"peers": self.server.store.peers()})
        elif path == "/api/v1/policies":
            self.reply(200, {"policies": self.server.store.policies()})
        elif path == "/api/v1/dns":
            self.reply(200, {"records": self.server.store.dns_records(), "dns_server_running": False})
        elif path == "/api/v1/events":
            try:
                query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=4)
                self.keys(query, {"limit", "before", "peer_id", "kind"})
                if any(len(values) != 1 for values in query.values()):
                    raise ValidationError("duplicate query parameters")
                filters = {name: values[0] for name, values in query.items()}
                for name in ("limit", "before"):
                    if name in filters:
                        if not filters[name].isascii() or not filters[name].isdigit():
                            raise ValidationError("invalid numeric event filter")
                        filters[name] = int(filters[name])
                self.reply(200, self.server.store.event_page(**filters))
            except (ValidationError, ValueError):
                self.reply(400, {"error": "invalid event filters"})
        elif path.startswith("/api/v1/peers/") and path.endswith("/plan"):
            peer_id = path[len("/api/v1/peers/"):-len("/plan")]
            if not peer_id or "/" in peer_id:
                self.reply(404, {"error": "not found"})
                return
            try:
                self.reply(200, {"plan": build_peer_plan(self.server.store, peer_id)})
            except ValidationError:
                self.reply(404, {"error": "peer absent or not approved"})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if not self.trusted_request():
            return
        if not self.authorized():
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/peers/") and (
            path.endswith("/approve") or path.endswith("/revoke")
        ):
            action = "approve" if path.endswith("/approve") else "revoke"
            peer_id = path[len("/api/v1/peers/"):-len("/" + action)]
            if not peer_id or "/" in peer_id:
                self.reply(404, {"error": "not found"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Transfer-Encoding", []) or len(lengths) > 1
                    or (lengths and lengths[0] != "0")):
                self.reply(400, {"error": "state transitions do not accept a request body"})
                return
            transitioned = (self.server.store.approve_peer(peer_id) if action == "approve"
                            else self.server.store.revoke_peer(peer_id))
            self.reply(200 if transitioned else 404, {
                action + "d": transitioned, "data_plane_enforced": False
            })
            return
        if path not in ("/api/v1/peers", "/api/v1/policies", "/api/v1/access/check",
                        "/api/v1/access/explain", "/api/v1/access/simulate"):
            self.reply(404, {"error": "not found"})
            return
        try:
            body = self.body()
            if path == "/api/v1/peers":
                self.keys(body, {"name", "public_key", "groups", "endpoint"})
                result = {"peer": self.server.store.add_peer(body.get("name"), body.get("public_key"),
                                                              body.get("groups"), body.get("endpoint"))}
                status = 201
            elif path == "/api/v1/policies":
                self.keys(body, {"source", "target", "protocol", "ports"})
                result = {"policy": self.server.store.add_policy(
                    body.get("source"), body.get("target"), body.get("protocol"), body.get("ports"))}
                status = 201
            elif path == "/api/v1/access/simulate":
                self.keys(body, {"checks"})
                result = simulate_access(self.server.store, body.get("checks"))
                status = 200
            elif path == "/api/v1/access/explain":
                self.keys(body, {"source_id", "target_id", "protocol", "port"})
                result = self.server.store.explain_access(
                    body.get("source_id"), body.get("target_id"), body.get("protocol"), body.get("port"))
                status = 200
            else:
                self.keys(body, {"source_id", "target_id", "protocol", "port"})
                result = {"allowed": self.server.store.allowed(
                    body.get("source_id"), body.get("target_id"), body.get("protocol"), body.get("port")),
                    "data_plane_enforced": False}
                status = 200
            self.reply(status, result)
        except ValidationError as exc:
            self.reply(400, {"error": str(exc)})
        except Exception:
            LOG.exception("unexpected management error")
            self.reply(500, {"error": "internal error"})

    @staticmethod
    def keys(body, allowed):
        if set(body) - allowed:
            raise ValidationError("unexpected request fields")

    def do_DELETE(self):
        if not self.trusted_request() or not self.bodyless_request():
            return
        if not self.authorized():
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/peers/"):
            found = self.server.store.delete_peer(path[len("/api/v1/peers/"):])
        elif path.startswith("/api/v1/policies/"):
            found = self.server.store.delete_policy(path[len("/api/v1/policies/"):])
        else:
            self.reply(404, {"error": "not found"})
            return
        self.reply(200 if found else 404, {
            "revoked": found, "metadata_retained": True, "data_plane_enforced": False
        })

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler logs the entire request target by default,
        # including query parameters. Avoid secrets in local audit logs.
        status = args[1] if len(args) >= 2 and str(args[1]).isdigit() else "unknown"
        LOG.info("loopback management HTTP status=%s", status)


def create_server(store, token, host="127.0.0.1", port=8176):
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError("management host must be a loopback IP") from exc
    if not address.is_loopback:
        raise ValidationError("management interface must be loopback only")
    if not isinstance(token, str) or not 32 <= len(token) <= 4096:
        raise ValidationError("admin token must be at least 32 characters")
    server_class = _IPv6ThreadingHTTPServer if address.version == 6 else _BoundedManagementHTTPServer
    server = server_class((host, port), Handler)
    server.daemon_threads = True
    server.socket_timeout_seconds = MANAGEMENT_SOCKET_TIMEOUT_SECONDS
    server.store = store
    server.admin_token = token
    return server


def main():
    parser = argparse.ArgumentParser(description="GoreeCloud VPN local management alpha")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8176)
    parser.add_argument("--db", default=os.environ.get(
        "GOREECLOUD_VPN_DB", "~/.local/share/goreecloud-vpn/state.db"))
    parser.add_argument("--subnet", default="10.234.12.0/24")
    parser.add_argument("--domain", default="vpn.internal")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    os.umask(0o077)
    try:
        store = VPNStore(args.db, args.subnet, args.domain)
        server = create_server(store, os.environ.get("GOREECLOUD_VPN_ADMIN_TOKEN", ""),
                               args.host, args.port)
    except ValidationError as exc:
        parser.error(str(exc))
    try:
        LOG.info("Local management listening on %s:%s", args.host, server.server_port)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()

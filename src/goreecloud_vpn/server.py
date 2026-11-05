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
from urllib.parse import parse_qs, urlsplit

from .core import VPNStore, ValidationError
from .plan import build_peer_plan
from .enrollment import ProofChallenges
from .diagnostics import management_status, policy_diagnostics, simulate_access

LOG = logging.getLogger("goreecloud_vpn")


class _IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    """Bind the IPv6 loopback with an IPv6 socket, never an IPv4 wildcard."""
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    server_version = "GoreeCloudVPN-alpha"

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

    def authorized(self):
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer ") or not hmac.compare_digest(
            value[7:].encode("utf-8"), self.server.admin_token.encode("utf-8")
        ):
            self.reply(401, {"error": "unauthorized"})
            return False
        return True

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValidationError("chunked body not supported")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as exc:
            raise ValidationError("Content-Length required") from exc
        if not 0 <= length <= 16384:
            raise ValidationError("body size limit exceeded")
        if self.headers.get_content_type() != "application/json":
            raise ValidationError("Content-Type must be application/json")
        try:
            result = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("invalid JSON") from exc
        if not isinstance(result, dict):
            raise ValidationError("expected JSON object")
        return result

    def do_GET(self):
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
        if not self.authorized():
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/peers/") and (
            path.endswith("/challenge") or path.endswith("/prove")
        ):
            action = "challenge" if path.endswith("/challenge") else "prove"
            peer_id = path[len("/api/v1/peers/"):-len("/" + action)]
            if not peer_id or "/" in peer_id:
                self.reply(404, {"error": "not found"})
                return
            try:
                if action == "challenge":
                    if (self.headers.get("Transfer-Encoding") or
                            self.headers.get("Content-Length", "0") != "0"):
                        raise ValidationError("challenge creation accepts no body")
                    result = {"challenge": self.server.proofs.issue(peer_id)}
                    status = 201
                else:
                    payload = self.body()
                    self.keys(payload, {"challenge_id", "proof"})
                    success = self.server.proofs.verify(
                        peer_id, payload.get("challenge_id"), payload.get("proof")
                    )
                    result = {"verified": success, "data_plane_enforced": False}
                    status = 200 if success else 400
                self.reply(status, result)
            except ValidationError as exc:
                self.reply(400, {"error": str(exc)})
            return
        if path.startswith("/api/v1/peers/") and (
            path.endswith("/approve") or path.endswith("/revoke")
        ):
            action = "approve" if path.endswith("/approve") else "revoke"
            peer_id = path[len("/api/v1/peers/"):-len("/" + action)]
            if not peer_id or "/" in peer_id:
                self.reply(404, {"error": "not found"})
                return
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
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
        LOG.info("%s %s", self.address_string(), fmt % args)


def create_server(store, token, host="127.0.0.1", port=8176):
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError("management host must be a loopback IP") from exc
    if not address.is_loopback:
        raise ValidationError("management interface must be loopback only")
    if not isinstance(token, str) or not 32 <= len(token) <= 4096:
        raise ValidationError("admin token must be at least 32 characters")
    server_class = _IPv6ThreadingHTTPServer if address.version == 6 else ThreadingHTTPServer
    server = server_class((host, port), Handler)
    server.daemon_threads = True
    server.store = store
    server.admin_token = token
    server.proofs = ProofChallenges(store)
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

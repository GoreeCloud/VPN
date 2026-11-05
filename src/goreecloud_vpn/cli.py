"""Local inspection client. No network configuration, redirects or proxy use."""
import argparse
from http.client import HTTPConnection, HTTPException
import ipaddress
import json
import os
import sys
from urllib.parse import urlencode
from uuid import UUID

from .core import ValidationError

MAX_RESPONSE = 1024 * 1024


def request(host, port, token, path, body=None):
    # Literal loopback addresses only: never send the admin token to a hostname,
    # environment-configured proxy, remote address, or redirect destination.
    try:
        address = ipaddress.IPv4Address(host)
    except (ValueError, TypeError) as exc:
        raise ValidationError("host must be a literal IPv4 loopback address") from exc
    if not address.is_loopback:
        raise ValidationError("host must be a literal IPv4 loopback address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValidationError("port must be between 1 and 65535")
    if not isinstance(token, str) or not 32 <= len(token) <= 4096 or any(
        not 33 <= ord(char) <= 126 for char in token
    ):
        raise ValidationError("set GOREECLOUD_VPN_ADMIN_TOKEN to 32–4096 printable ASCII characters without spaces")
    payload = json.dumps(body).encode() if body is not None else None
    if payload is not None and len(payload) > 16384:
        raise ValidationError("body size limit exceeded")
    conn = HTTPConnection(str(address), port, timeout=5)
    try:
        headers = {"Authorization": "Bearer " + token}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        conn.request("POST" if payload is not None else "GET", path, body=payload, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            raise ValidationError(f"management request failed (HTTP {response.status}); redirects are not followed")
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValidationError("response size limit exceeded")
        try:
            return json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("management response was not valid JSON") from exc
    finally:
        conn.close()


def peer_id(value):
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a peer UUID") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="GoreeCloud VPN local management inspection (not a VPN client)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8176)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "peers", "policies", "dns", "diagnostics"):
        commands.add_parser(name)
    events = commands.add_parser("events")
    events.add_argument("--limit", type=int, default=200)
    events.add_argument("--before", type=int)
    events.add_argument("--peer-id", type=peer_id)
    events.add_argument("--kind", choices=("peer_registered", "peer_approved", "peer_revoked"))
    plan = commands.add_parser("plan")
    plan.add_argument("peer_id", type=peer_id)
    explain = commands.add_parser("explain")
    explain.add_argument("source_id", type=peer_id)
    explain.add_argument("target_id", type=peer_id)
    explain.add_argument("protocol", choices=("tcp", "udp", "icmp"))
    explain.add_argument("--port", dest="flow_port", type=int)
    commands.add_parser("simulate", help='read {"checks": [...]} JSON from stdin (16 KiB maximum)')
    args = parser.parse_args(argv)
    body = None
    path = "/api/v1/" + args.command
    if args.command == "diagnostics":
        path = "/api/v1/policies/diagnostics"
    elif args.command == "events":
        filters = {key: getattr(args, key) for key in ("limit", "before", "peer_id", "kind")
                   if getattr(args, key) is not None}
        path += "?" + urlencode(filters)
    elif args.command == "plan":
        path = "/api/v1/peers/" + args.peer_id + "/plan"
    elif args.command == "explain":
        path = "/api/v1/access/explain"
        body = {"source_id": args.source_id, "target_id": args.target_id,
                "protocol": args.protocol, "port": args.flow_port}
    try:
        if args.command == "simulate":
            path = "/api/v1/access/simulate"
            data = sys.stdin.read(16385)
            if len(data.encode("utf-8")) > 16384:
                raise ValidationError("body size limit exceeded")
            try:
                body = json.loads(data)
            except ValueError as exc:
                raise ValidationError("stdin must contain a JSON object with checks") from exc
            if not isinstance(body, dict):
                raise ValidationError("stdin must contain a JSON object with checks")
        result = request(args.host, args.port, os.environ.get("GOREECLOUD_VPN_ADMIN_TOKEN", ""), path, body)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ValidationError as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, HTTPException):
        # Do not print raw transport exceptions, headers, or credentials.
        print("Error: could not reach the local management API", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

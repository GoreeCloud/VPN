#!/usr/bin/env python3
"""Create a brand-new NetBird control plane; never import or reuse old state.

Python 3.10+, stdlib only. Run in a *new*, absent directory. The generated
password is owner-only and must be rotated and removed after first sign-in.
"""
import argparse
import base64
import ipaddress
import os
from pathlib import Path
import re
import secrets
import sys

def secure_file(path: Path, value: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(value)
    os.chmod(path, 0o600)

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize a NetBird instance with new empty data and fresh credentials."
    )
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--domain", default="netbird.goreecloud.com")
    parser.add_argument("--owner-email", default="admin@goreecloud.com")
    parser.add_argument("--trusted-proxy-ip", required=True,
                        help="Verified Caddy container IPv4, not a public wildcard")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{2,250}", args.domain):
        parser.error("A valid HTTPS DNS hostname is required.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", args.owner_email):
        parser.error("A valid owner email is required.")
    try:
        proxy = ipaddress.ip_address(args.trusted_proxy_ip)
    except ValueError:
        parser.error("Trusted proxy must be one concrete IP.")
    if proxy.version != 4 or not proxy.is_private:
        parser.error("Trusted proxy must be an internal Docker IPv4.")
    base = args.directory.expanduser().absolute()
    if base.exists() or base.is_symlink():
        parser.error("Target already exists. Refusing to reuse a previous NetBird state.")
    if not base.parent.is_dir():
        parser.error("Parent directory must already exist.")

    os.umask(0o077)
    base.mkdir(mode=0o700)
    for name in ("data", "client-state", "credentials"):
        (base / name).mkdir(mode=0o700)
    password = secrets.token_urlsafe(36)
    relay_key = secrets.token_urlsafe(48)
    store_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    cidr = f"{proxy}/32"
    config = f"""server:
  listenAddress: ":80"
  exposedAddress: "https://{args.domain}:443"
  stunPorts:
    - 3478
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"
  authSecret: "{relay_key}"
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "https://{args.domain}/oauth2"
    localAuthDisabled: false
    signKeyRefreshEnabled: true
    dashboardRedirectURIs:
      - "https://{args.domain}/nb-auth"
      - "https://{args.domain}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"
    owner:
      email: "{args.owner_email}"
      password: "{password}"
  reverseProxy:
    trustedHTTPProxies:
      - "{cidr}"
    trustedPeers:
      - "{cidr}"
  store:
    engine: "sqlite"
    encryptionKey: "{store_key}"
"""
    dashboard = f"""NETBIRD_MGMT_API_ENDPOINT=https://{args.domain}
NETBIRD_MGMT_GRPC_API_ENDPOINT=https://{args.domain}
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=https://{args.domain}/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
NGINX_SSL_PORT=443
LETSENCRYPT_DOMAIN=none
"""
    secure_file(base / "config.yaml", config)
    secure_file(base / "dashboard.env", dashboard)
    secure_file(base / "credentials" / "initial-admin-password", password + "\n")
    print("Brand-new NetBird config and empty state created (directories 0700, files 0600).")
    print("Initial administrator password stored privately in credentials/initial-admin-password.")
    print("No prior accounts, peers, policies, keys, databases, or backup data were imported.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

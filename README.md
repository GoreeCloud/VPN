# VPN

The [`deploy/netbird/`](deploy/netbird/README.md) directory contains the reviewed **non-secret** Docker Compose, NetBird peer enrollment helper, existing-Caddy routing snippet, safety tests, and VPS Mesh recovery/acceptance runbook. Live private settings, recovered data, setup keys, CA private keys, and credentials are never part of this public repository.

**Status (November 20, 2026):** The restored NetBird management dashboard and server are running through Caddy HTTPS; AdGuard's VPN-only Caddy route denies public traffic. VPS peer enrollment, laptop reauthentication, custom private DNS and end-to-end AdGuard access remain **pending** until authorized setup/login and live VPN address verification. Do not confuse source templates with a completed VPN tunnel.

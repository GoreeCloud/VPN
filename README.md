# VPN

The [`deploy/netbird/`](deploy/netbird/README.md) folder contains the **fresh-from-zero** NetBird Docker installation, credential bootstrap helper, guarded Caddy and AdGuard routes, an enrollment helper, tests, and security/recovery procedures. The source contains no historic NetBird database, identities, or private keys.

**Live VPS checkpoint (November 20, 2026):** New NetBird combined server and dashboard are running with independent generated credentials and a new empty management database. The previous restored deployment containers and runtime directory were removed. Caddy exposes the public NetBird sign-in and returns 404 to public requests for VPN-only AdGuard. First sign-in, new peer enrollment, private DNS and end-to-end AdGuard access are not yet verified; see the deployment runbook.

# VPN

The [`deploy/netbird/`](deploy/netbird/README.md) folder contains the **fresh-from-zero** NetBird Docker installation, credential bootstrap helper, guarded Caddy and AdGuard routes, an enrollment helper, tests, and security/recovery procedures. The source contains no historic NetBird database, identities, or private keys.

**Live VPS checkpoint (November 20, 2026):** New NetBird combined server and dashboard are running with independent generated credentials and a new empty management database. The previous restored deployment containers and runtime directory were removed. Caddy exposes the public NetBird sign-in and returns 404 to public requests for VPN-only AdGuard. First sign-in, new peer enrollment, private DNS and end-to-end AdGuard access are not yet verified; see the deployment runbook.

## NetBird management CLI

[Source-managed gc-netbird REST administration CLI](tools/netbird-cli/README.md) runs on the authorized VPS and can be invoked from Remote Desktop Commander. It supports peer/group/policy inventory, authenticated REST read/write for groups, policies, DNS and other documented resources, offline --dry-run validation, private output files and dual write confirmations. Local fresh SQLite peer/group/policy inventory works without a token; **live authenticated API use still requires an owner-generated PAT enrolled in a private interactive VPS terminal**. Never confuse an installed CLI or passing simulated tests with a proven live production policy change.

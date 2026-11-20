# Security policy

**Development preview; no production security acceptance.** Do not rely on this version as your sole secure remote-access path.

Report vulnerabilities privately using GitHub security advisories if enabled. Do not expose credentials, real network identifiers, private keys, exploit payloads or private user data in public issues.

- Backend: numeric-loopback HTTP, admin bearer token, strict input validation and no default public exposure.
- Web: separate HMAC session cookie, server-only upstream bearer, origin validation. Local use only until trusted HTTPS, OIDC/RBAC and comprehensive session/proxy hardening are in place.
- Linux: polkit authorization; config must be root-owned and private. Review all wireguard-tools hook directives (PostUp, PreDown, etc.) before installing because wg-quick may execute shell commands as root.
- Android: operating-system VPN permission and temporary in-memory imported configuration; FLAG_SECURE; no app-level analytics.
- Peer revocation is a STORE CHANGE ONLY until the server config is reapplied. Data plane enforcement and DNS/IPv6/routing are NOT verified.
- Android and Linux data planes use upstream WireGuard implementations; no custom cryptographic implementation.

Release blockers include signed binaries, threat review, dependency/SBOM audit, Identity, GoreeShield, Wardveil, live ACL/revocation tests, DNS leak checks, IPv6, resilient key handling, two-device path tests, backups and rollback.

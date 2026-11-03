# GoreeCloud VPN — implementation plan and acceptance criteria

**As of November 3, 2026.** All unmarked capabilities remain planned. See [FEATURES](FEATURES.md) for the complete product scope.

## Foundation delivered to repository

- [x] Installable Python package and standard-library API.
- [x] Loopback-only bearer-authenticated administrative interface.
- [x] Private IPv4 allocation, peer name/key/group metadata and SQLite persistence.
- [x] Explicit pending/approved/revoked lifecycle, fail-closed schema migration and terminal revocation of management records.
- [x] Pending/revoked peer exclusion from management policy decisions and private DNS previews.
- [x] Local lifecycle history and regression tests (not tamper-proof auditing).
- [x] Read-only WireGuard adjacency planning for approved peers and offline peer stanzas.
- [x] RFC1918-only IPv4 pool validation and authenticated peer planning preview.
- [x] Preliminary threat model and explicit acceptance gates.
- [x] Directional TCP/UDP/ICMP default-deny **policy evaluation only**.
- [x] DNS record preview (not a DNS service).
- [x] Input checks, body limits, owner file permissions, unit/HTTP tests and CI configuration.
- [ ] Verified CI success across all configured Python versions.

## Priority 0 — establish a real secure VPN

- [ ] Threat model, security review and architecture decision on client engine.
- [ ] Client-held key generation and authenticated proof-of-possession enrollment.
- [ ] WireGuard tunnel/peer lifecycle and server-client coordination.
- [ ] Enforce identity/policy in actual data plane, including deny/revoke tests.
- [ ] TLS/mTLS for remote management and enrollment.
- [ ] STUN/NAT traversal, direct connections, encrypted relay fallback.
- [ ] Integration tests across isolated hosts, networking namespaces and reboots.
- [ ] Rollback, backup, recovery and non-interference with existing NetBird service.

## Priority 1 — functional self-hosted networking

- [ ] Subnet routing, exit nodes, split/full tunnels, IPv6 and failover.
- [ ] Private DNS server, internal zones, split DNS, route resolution and diagnostics.
- [ ] OIDC/SSO, RBAC, service identities and per-device lifecycle.
- [ ] Hardened deployment, metrics, backup automation and recoverability.
- [ ] Linux agent plus platform-specific Windows/macOS/Android/iOS development.
- [ ] GoreeCloud UI console, tested visually and for accessibility.

## Priority 2 — application and enterprise platform

- [ ] Authenticated service publishing and reverse proxy.
- [ ] SSH/RDP administration, privileged sessions and file transfer.
- [ ] Audit, flow logs, posture policies, EDR/MDM, SCIM, tenant isolation.
- [ ] Kubernetes, Terraform, GitOps, API and CI/CD automations.
- [ ] AI gateway identity/usage governance, secure MCP integration.
- [ ] High availability, performance testing, enterprise monitoring and compliance checks.

## Release gates

Security defaults, integration behavior, production deployment, cross-platform support and design quality are independently verified. Unit tests alone never imply live VPN behavior or production readiness. The current repository is a **pre-production alpha foundation**, not a deployed VPN.

# GoreeCloud VPN — implementation plan and acceptance criteria

**As of November 7, 2026.** All unmarked capabilities remain planned. See [FEATURES](FEATURES.md) for the complete product scope.

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
- [x] Individual repository MIT license, README scope and SPDX package metadata (PR #16).
- [x] Exact loopback Host and browser Origin request boundaries with IPv4/IPv6 regressions (PR #17).
- [x] Nonpublishing Python wheel build and included license/SPDX/package integrity validation (PR #18).
- [x] Verified GitHub PR CI success on Python 3.11, 3.12 and 3.13, including wheel gates in PR #18.
- [x] Local clean-checkout management baseline: 53 tests passed on Python 3.12 after packaging gates.
- [x] Read-only Linux WireGuard lab prerequisite checker and regression tests (PR #19).
- [x] Manual, explicitly opt-in rootless network/mount namespace WireGuard kernel handshake, nftables drop, rule restore and peer removal smoke, private tmpfs keys and safety-guard tests (PR #20).
- [x] Clean-checkout Python 3.12 lab branch: 62 tests; GitHub CI Python 3.11/3.12/3.13 successful, Bash syntax-only in CI. **Not** a GoreeCloud-managed data plane.
- [x] Experimental **read-only** nftables IPv4 INPUT policy compiler merged in PR #21; manually applied in disposable rootless lab only. Generated ICMP deny/allow and peer removal were verified in kernel; Python 3.11/3.12/3.13 CI passed.
- [x] Generated TCP 8443 and UDP 5353 allow versus listening TCP 8444 and UDP 5354 deny tested over real encrypted WireGuard in isolated lab (PR #23). Exact-head 73 local tests and GitHub CI Python 3.11/3.12/3.13 passed. **Neither PR implements an agent or production packet enforcement.**
- [x] Experimental **offline** nftables `flush chain`/`add rule` replacement preview and manually verified rejection of a malformed batch while preserving the prior kernel deny (PR #24). Exact-head 75 Python 3.12 tests and GitHub CI Python 3.11/3.12/3.13 passed. This does **not** implement authenticated, atomic production policy rollout, cross-hook traffic control or conntrack revocation.
- [x] Real WireGuard source-address `/32` spoof-denial and reverse-direction INPUT default-deny checks in rootless isolation (PR #25); exact-head 76 local Python 3.12 tests and GitHub CI Python 3.11/3.12/3.13 passed. Stateless return-flow correctness is not solved.
- [x] Read-only, fail-closed approved-peer canonical public-key to unique private IPv4 `/32` binding intent with unauthenticated SHA-256 change fingerprint (PR #26); exact-head 81 local Python 3.12 tests, wheel metadata validation and 3-version CI passed. Does not establish device possession, active kernel AllowedIPs, or enforcement.
- [x] Disposable kernel test confirms an **already established** TCP stream loses subsequent application traffic after manual rule withdrawal, and fresh connection succeeds after reallow (PR #27); exact-head 83 local Python 3.12 tests and GitHub CI Python 3.11/3.12/3.13 passed. Full conntrack/session-revocation guarantee still open.
- [x] Strict offline parser for public-only WireGuard AllowedIPs text compared with selected approved key-to-/32 intent; manual rootless lab verifies actual kernel public readback with no private-key dump (PR #28). Exact-head 92 local Python 3.12 tests, kernel regression and GitHub CI Python 3.11/3.12/3.13 passed. **Not** an attested production agent.
- [x] Experimental **single-snapshot offline ingress preflight** combines approved public key/IP binding intent, group-policy/port nftables preview, and public-key readback within one frozen management generation; absent, unauthorized or mismatched selected sources fail closed. Explicit flags prohibit claims of agent authority or production enforcement. Merged PR #29: 103 exact-head local Python tests, wheel validation, rootless kernel test and Python 3.11/3.12/3.13 GitHub CI passed.
- [x] Offline nftables INPUT preview ends in **WireGuard interface-wide drop**, verified on a second local IP reachable before the filter and blocked both under default deny and after an allow to the intended target (PR #30; 104 tests and CI Python 3.11/3.12/3.13 passed). Still not a production firewall.
- [x] Guarded, explicitly opted-in **rootless lab-only** transaction helper consumes actual public WireGuard readback, a single local approved policy snapshot and fixed validated nft rules; refuses an injected unapproved kernel peer with **no change** in the live lab nft chain. Python 3.12 local suite 106 tests; GitHub PR and CI review required.

## Management inspection additions

- [x] Authenticated management status and group/address-pool inventory.
- [x] Explainable access evaluation and bounded current-policy batch simulation.
- [x] Static duplicate/unused-policy diagnostics and cursor-paginated event history.
- [x] Local read-only administration CLI with JSON output.

See [management inspection](MANAGEMENT_INSPECTION.md). These additions do not
complete any identity, data-plane, live telemetry or production deployment gate.

## Priority 0 — establish a real secure VPN

- [ ] Threat model, security review and architecture decision on client engine.
- [ ] Client-held key generation and authenticated production enrollment. Local key-possession prototype in draft PR #6 remains unmerged, under independent cryptographic review and branch-reconciliation gates.
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

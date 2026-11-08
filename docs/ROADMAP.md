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
- [x] Stronger wheel archive integrity gate verifies **all** recorded members using secure RECORD digests and sizes; negative tests cover tampered code/license, omitted/unrecorded members, weak hashes, unsafe ZIP paths, unexpected private files and duplicate entries. PR #35 merged after 129 exact-head tests and GitHub CI 3.11/3.12/3.13. This is artifact consistency, **not** signed provenance, full SBOM or release attestation.
- [x] Pin existing GitHub CI actions to **verified full SHA** from upstream `actions/checkout` v4.4.0 and `actions/setup-python` v5.6.0 and add regression tests requiring SHA-only external references, read-only job permissions, PR-safe triggers and preserved nonpublishing wheel gates. PR #36 merged after 132 exact-head Python 3.12 tests, wheel integrity and GitHub CI 3.11/3.12/3.13 passed.
- [x] Experimental **offline-only SQLite revision high-water ledger** with per-device audience ordering across controller signer key rotation, serialized local compare-and-swap, owner-only storage and adversarial concurrency/reopen tests. A test demonstrates full-database restore **rolls the counter backward**; only draft PR #34 test code composes verified signatures with the local floor. No privileged/kernel policy enforcement or tamper-resistant replay protection is integrated.
- [ ] Independent security review of **draft PR #34's offline-only signed-policy envelope** before removing draft status or connecting any privileged action: dedicated Ed25519 controller key, bounded domain-separated signature/audience/time/sequence checks, optional reviewed dependency; trusted key provisioning, atomic durable anti-replay counter, authenticated issuer and independent protocol review **not implemented**.
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
- [x] Guarded, explicitly opted-in **rootless lab-only** transaction helper consumes actual public WireGuard readback, a single local approved policy snapshot and fixed validated nft rules; refuses an injected unapproved kernel peer with **no change** in the live lab nft chain. PR #31 merged after 106 exact-head Python 3.12 tests, wheel metadata verification, rootless kernel testing and GitHub Python 3.11/3.12/3.13 CI.
- [x] Test-only exact JSON nftables chain validation before and after lab policy replacement, rejecting injected extra accept and unchanged chain on refusal. This addresses permissive text matching (PR #32 merged after 115 tests, exact kernel checks and Python 3.11/3.12/3.13 CI); it does **not** implement atomic peer/chain trust, generation-pinned authorization, or durable production recovery.
- [x] Test-only **forced post-apply readback failure** now exercises compiler-generated default-deny fallback, exact JSON kernel verification and negative packet test before restoring the expected lab chain. PR #33 merged after 117 exact-head Python 3.12 tests, wheel integrity, manual isolated kernel regression and GitHub CI 3.11/3.12/3.13. This proves one **manual rootless** fallback scenario, not restart/crash-safe or production rollback.

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

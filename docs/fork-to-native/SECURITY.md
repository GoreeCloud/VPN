# Security baseline and release restrictions

**Source-import development stage only.** Limited Go package tests, static analysis, and headless source builds of the inherited `signal` and `relay` packages have been introduced. No full-product compilation, independent vulnerability assessment, VPN runtime verification, packet-level validation, or production acceptance has been completed.

## Non-negotiable release gates

- No automatically inherited deployment, release, synchronization, cloud enrollment, or upstream publishing workflows.
- No default connection or transmission to an upstream commercial service presented as a GoreeCloud-controlled endpoint; review every management, signal, relay, STUN/TURN, telemetry and update endpoint.
- Preserve trustworthy WireGuard crypto and key handling; never log keys, secrets, private addresses or authentication tokens.
- Test MFA/SSO enforcement, local-to-remote authorization, route and DNS settings, kill-switch or fail-closed behavior (where offered), IPv6 handling, suspend/resume, captive portals and network changes.
- Verify access-control precedence and revocation across clients/services. Require explicit consent for routing all traffic or altering device firewall/network permissions.
- Assess supply-chain attack paths, build signing and SBOM before owner-facing binaries.
- Treat AGPL-covered `management/`, `signal/`, `relay/` and `combined/` components and their modifications as requiring license-specific distribution/network-service compliance review.

## Metrics privacy progress (development only)

The inherited NetBird metrics push integration now requires an explicit remote configuration endpoint (`NB_METRICS_CONFIG_URL`) for remote configuration fetching. Setting `NB_METRICS_FORCE_SENDING=true` without an explicit `NB_METRICS_SERVER_URL` causes an error rather than selecting the upstream NetBird ingestion service. Regression tests cover these cases. Operators must still deliberately evaluate and configure any optional metric collection and upload, including server-controlled push settings.

These checks address one inherited telemetry pathway only. They do not certify that other client, UI, control-plane, update or debug-upload destinations are GoreeCloud-owned or offline-safe. See the endpoint audit in GitHub issue #5.

## Current known limitations

The snapshot is inherited upstream code with upstream product names, URLs, Go module identity, policies, and dependencies. It is **not** independently hardened, not a verified privacy shield, and not suitable for representation as a GoreeCloud production VPN. Upstream workflows are excluded but any future workflow added to this repository must receive a separate security audit.

All acceptance evidence must identify exact commit, test environment and results. Security claims without evidence are prohibited.


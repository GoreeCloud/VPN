# Security baseline and release restrictions

**Source-import development stage only.** Scoped Go tests and static analysis pass, and exact-head CI compiled all five inherited primary Linux Go entrypoint packages without starting services. No full cross-platform product compilation, independent vulnerability assessment, VPN runtime verification, packet-level validation, or production acceptance has been completed.

## Non-negotiable release gates

- No automatically inherited deployment, release, synchronization, cloud enrollment, or upstream publishing workflows.
- No default connection or transmission to an upstream commercial service presented as a GoreeCloud-controlled endpoint; review every management, signal, relay, STUN/TURN, telemetry and update endpoint.
- Preserve trustworthy WireGuard crypto and key handling; never log keys, secrets, private addresses or authentication tokens.
- Test MFA/SSO enforcement, local-to-remote authorization, route and DNS settings, kill-switch or fail-closed behavior (where offered), IPv6 handling, suspend/resume, captive portals and network changes.
- Verify access-control precedence and revocation across clients/services. Require explicit consent for routing all traffic or altering device firewall/network permissions.
- Assess supply-chain attack paths, build signing and SBOM before owner-facing binaries.
- Treat AGPL-covered `management/`, `signal/`, `relay/` and `combined/` components and their modifications as requiring license-specific distribution/network-service compliance review.

## Reverse proxy management defaults (development only)

The inherited reverse proxy had a NetBird-hosted management URL default. The development source now requires an explicit `--mgmt` or `NB_PROXY_MANAGEMENT_ADDRESS` for startup, with regression tests. Other endpoints, deployments and runtime behavior remain unverified.

## Metrics privacy progress (development only)

The inherited NetBird metrics push integration now requires an explicit remote configuration endpoint (`NB_METRICS_CONFIG_URL`) for remote configuration fetching. Setting `NB_METRICS_FORCE_SENDING=true` without an explicit `NB_METRICS_SERVER_URL` causes an error rather than selecting the upstream NetBird ingestion service. Regression tests cover these cases. Operators must still deliberately evaluate and configure any optional metric collection and upload, including server-controlled push settings.

These checks address one inherited telemetry pathway only. They do not certify that other client, UI, control-plane, update or debug-upload destinations are GoreeCloud-owned or offline-safe. See the endpoint audit in GitHub issue #5.

## Remote diagnostic job upload guard

Remote diagnostic jobs now require an explicitly configured HTTPS upload endpoint. Invalid or inherited upstream addresses fail before collecting logs. Scoped regression tests cover this path. Other mobile, CLI and SDK upload paths remain unverified and require independent authorization review.

## Current known limitations

The snapshot is inherited upstream code with upstream product names, URLs, Go module identity, policies, and dependencies. It is **not** independently hardened, not a verified privacy shield, and not suitable for representation as a GoreeCloud production VPN. Upstream workflows are excluded but any future workflow added to this repository must receive a separate security audit.

All acceptance evidence must identify exact commit, test environment and results. Security claims without evidence are prohibited.

## Desktop diagnostic upload safety (development only)

The inherited desktop diagnostics UI previously enabled uploads by default to a NetBird-hosted service. The source now defaults to local-only bundles and requires both an explicit user opt-in and an operator-defined HTTPS destination through `VITE_GOREECLOUD_DEBUG_UPLOAD_URL`. Inherited NetBird/Wiretrustee domains are rejected. Scoped Node tests validate these source-level guards. This does not establish all upload pathways, package runtime behavior, or product-wide privacy acceptance.

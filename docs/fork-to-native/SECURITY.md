# Security baseline and release restrictions

**Source-import development stage only.** Limited Go package tests and static analysis have been introduced, but no full-product compilation, independent vulnerability assessment, VPN runtime verification, packet-level validation, or production acceptance has been completed.

## Non-negotiable release gates

- No automatically inherited deployment, release, synchronization, cloud enrollment, or upstream publishing workflows.
- No default connection or transmission to an upstream commercial service presented as a GoreeCloud-controlled endpoint; review every management, signal, relay, STUN/TURN, telemetry and update endpoint.
- Preserve trustworthy WireGuard crypto and key handling; never log keys, secrets, private addresses or authentication tokens.
- Test MFA/SSO enforcement, local-to-remote authorization, route and DNS settings, kill-switch or fail-closed behavior (where offered), IPv6 handling, suspend/resume, captive portals and network changes.
- Verify access-control precedence and revocation across clients/services. Require explicit consent for routing all traffic or altering device firewall/network permissions.
- Assess supply-chain attack paths, build signing and SBOM before owner-facing binaries.
- Treat AGPL-covered `management/`, `signal/`, `relay/` and `combined/` components and their modifications as requiring license-specific distribution/network-service compliance review.

## Current known limitations

The snapshot is inherited upstream code with upstream product names, URLs, Go module identity, policies, and dependencies. It is **not** independently hardened, not a verified privacy shield, and not suitable for representation as a GoreeCloud production VPN. Upstream workflows are excluded but any future workflow added to this repository must receive a separate security audit.

All acceptance evidence must identify exact commit, test environment and results. Security claims without evidence are prohibited.


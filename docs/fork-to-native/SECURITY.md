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

## Automatic installer restriction (development only)

The inherited Windows and macOS automatic installers are disabled. Both the daemon's `RunInstallation` entry point and the detached updater's `Setup` entry point reject requests before downloading installers or signing metadata, modifying result files, launching processes, stopping applications, or restarting services. Direct updater invocation, dry-run settings and the `devartifactsign` build tag cannot enable installation. The manager reports automatic installation unsupported on all platforms, including when management requests forced installation.

This guard is deliberately not an operator-toggleable update channel. Removing it requires a reviewed implementation with GoreeCloud-owned signing roots and revocation, verified product/package identity, explicit authorization, artifact integrity, anti-downgrade, upgrade and rollback acceptance. Inherited updater source and legal notices remain for audited migration; their presence does not authorize installing NetBird packages. See release blocker [#32](https://github.com/GoreeCloud/VPN/issues/32).

Run `go test -count=1 ./client/internal/updater ./client/internal/updater/installer` for the manager and installer regression suites. CI also executes the installer policy tests natively on Linux, Windows and macOS with production and development signing build tags. This is a source-level restriction, not proof of a qualified signed update path. Version discovery and other outbound endpoints still require the separate audit in issue #5.

## Version discovery restriction (development only)

The inherited periodic version checker no longer defaults to `pkgs.netbird.io`. With no qualified GoreeCloud discovery channel, its endpoint is empty and startup returns without creating a polling loop or making an HTTP request. There is no operator environment switch to revive the inherited destination. This is separate from automatic installation and does not establish a signed update channel.

For internal test endpoints, requests capture the endpoint at construction, have a ten-second deadline, support cancellation during shutdown, and reject responses over 100 bytes even without Content-Length. Fetcher startup is single-use; shutdown is idempotent, waits for in-flight work, and prevents a queued start from running after a stop. Run `go test -race -count=1 ./version` for default-egress, cancellation, duplicate-start, stop-before-start and oversized-response regressions. This covers only the version-discovery path; issue #5 still governs the wider endpoint audit.

## Compact host-address boundary (development only)

`DecodeAddr` accepts only full host prefixes: /32 for IPv4 and /128 for IPv6. Use `DecodePrefix` for ACL networks, which preserves subnet masks and /0 wildcards. The host decoder rejects network-prefix input instead of silently narrowing a policy network to a peer. Existing mapped-IPv4 /32 wire values remain compatible and normalize to IPv4.

`EncodeAddrChecked` rejects invalid or interface-scoped addresses explicitly. Zones are checked before unmapping IPv4-mapped IPv6 so normalization cannot silently lose an interface scope. The legacy `EncodeAddr` API remains available and returns nil for unsupported values. Unit and ACL regressions, host-boundary fuzzing and a 32-bit CI test cover this source-level contract; actual management propagation and kernel firewall acceptance remain open in issue #2.

## Remote telemetry authorization lease (development only)

An optional remote telemetry destination is valid for at most two hours after its latest successfully validated configuration. Temporary transport failures, HTTP 408/429 and server errors may reuse only the remaining lease; failures never renew it. The exact expiry boundary stops optional telemetry even when the requested refresh interval is longer than the lease. A subsequently validated response can authorize it again.

Revocation responses, redirects, unexpected success statuses, permanent client errors, unreadable/oversized responses, malformed or duplicate JSON fields, invalid version windows and invalid destinations discard cached authorization immediately. Responses are limited to 4096 bytes, including streams without Content-Length, and minute-to-duration overflow is rejected. The configuration URL and remotely supplied upload destination must use credential-free HTTPS or explicit loopback HTTP for local development, without query strings or fragments. Redirects are not followed. An unset configuration endpoint still makes no request.

The metrics CI gate runs race-enabled regression tests. All foundation jobs pin checkout to the pull-request head or dispatch SHA to identify the exact tested source. These are scoped source/privacy checks; forced-send transport, the full outbound inventory, real network behavior and product-wide privacy acceptance remain separately governed by issue #5.

## Metrics upload redirect boundary (development only)

The metrics upload client refuses HTTP redirects, including 307/308 responses that could replay a compressed metrics body and peer-identity header to another recipient. Authorization for the configured upload destination does not authorize a redirect target. A redirect is a failed delivery, so the metrics batch is retained; a subsequent direct successful response may clear it normally. Regression fixtures cover 301, 302, 303, 307 and 308 without contacting the redirect target. This guard does not certify all explicit or forced-send destination settings or product-wide privacy behavior.

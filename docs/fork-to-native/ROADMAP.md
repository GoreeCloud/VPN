# Fork-to-Native roadmap and acceptance gates

## M0 — Controlled source foundation (this import)

- [x] Independently controlled `GoreeCloud/VPN` repository, with existing history preserved
- [x] Pinned upstream commit and license provenance recorded
- [x] Retained upstream legal notices and archived upstream README
- [x] Prevented unaudited upstream workflows from being imported
- [x] Added scope-limited foundation validation
- [x] Established initial portable Go unit-test scope (`base62`, `monotime`, `shared/netiputil`) and invalid-IP-prefix regression coverage, validated locally with Go 1.27.0 (full build unverified)
- [ ] Full Go compile, broader module/test matrix and clean build evidence (requires Go >=1.26.7 or compatible toolchain)
- [ ] Dependency/license and vulnerability scan with triage
- [ ] Feature and outbound-network-communications inventories

## M1 — Behavior, data, privacy, and security baseline

- [x] Correct inherited client ACL decoding to preserve management-specified IPv4/IPv6 CIDR masks and /0 wildcards; add malformed-deny and mixed-family regression tests (scoped Go test evidence only)
- [ ] Validate policy propagation from running management service through clients, real firewall backends, and revocation under network changes

Inventory peer connectivity, WireGuard key handling, enrollment/SSO/MFA, NAT traversal, DNS, routing, policy, daemon, management/signal/relay services, UI clients and installers. Document feature parity and unsupported behavior. Build an inbound/outbound endpoint and telemetry matrix, secret-handling review, AGPL obligations, STRIDE-style threat model, and security-response plan. Set fail-closed defaults and no implicit affiliation with upstream hosted control planes.

## M2 — GoreeCloud-native trust and integration boundaries

Implement and test independent GoreeCloud Identity and Policy boundaries; evaluate interoperability with GoreeCloud Mesh; isolate cryptographic material in appropriate platform stores; audit Privacy Shield, Wardveil, Everkeep, Manager and Observability hooks. Preserve safe cryptographic standards and justified low-level libraries.

## M3 — Glaze user experience and real native clients

Replace upstream-branded UX, onboarding, notifications, help, settings, icons and login with the currently approved Stable Glaze tokens/components. Build/test appropriate actual platform-native clients (not webview wrappers) with permissions, accessibility, secure upgrade/install and signing paths. Retain required legal attribution in About/licenses.

## M4 — Progressive independent architecture

Replace inherited product-defining workflows and service control with GoreeCloud-managed implementations in reviewable increments, with migration and rollback tests. Rework Go module/import paths only with full dependency and artifact compatibility testing. Remove unnecessary commercial/marketing integrations and upstream services without bypassing paid service entitlements or breaking legitimate user functionality.

## M5 — Acceptance and release

Require reproducible builds, complete platform test matrix, VPN networking/IPv4/IPv6/DNS leak tests, auth and authorization tests, secure secret/key lifecycle checks, fail-closed/network-transition tests, accessibility, privacy and AGPL compliance, migration/backup/rollback trials, signed artifacts, documentation and clean-install checks. Promotion to **Stable** needs independent release approval and observed runtime evidence. Classification becomes **Native** only when inherited product-defining architecture has passed native acceptance.

**Status:** M0 partly achieved; M1 contains only scoped ACL policy-decoding improvements, with runtime firewall behavior and service integration still unverified. Milestones M2–M5 are **planned, not implemented**. Never report planned integrations, privacy protections or native apps as deployed.


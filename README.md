# GoreeCloud VPN

**Development status: Fork-to-Native foundation. Not a validated or released GoreeCloud VPN product.**

GoreeCloud VPN is a planned GoreeCloud-native, privacy-conscious VPN and private-networking product. This repository contains a **source snapshot from [NetBird](https://github.com/netbirdio/netbird)** as the initial engineering foundation. Its inherited components are not yet a standalone, independently rebranded, tested, or production-ready GoreeCloud implementation.

## Coordinated networking platform

On October 12, 2026, the GoreeCloud owner designated **GoreeCloud Gateway, GoreeCloud VPN, and GoreeCloud DNS** as the **GoreeCloud Coordinated Networking Platform**. Within that coordinated family, VPN is responsible for encrypted private connectivity and approved device and remote access; [Gateway](https://github.com/GoreeCloud/gateway) owns HTTP/HTTPS ingress, reverse proxying, and controlled service publication; and [DNS](https://github.com/GoreeCloud/DNS) owns name resolution, filtering, and DNS policy. Coordination must preserve each product's independent authority and private-by-default access and publication boundaries.

This designation records the intended product architecture. It does **not** establish completed cross-product integration, validated GoreeCloud-native VPN behavior, deployment, or production readiness.

## Current scope

- Inherited upstream networking implementation includes WireGuard-based private networking, peer connectivity, and infrastructure components.
- The original Go module path and many upstream product identifiers remain intact during the audited import stage. **Do not interpret inherited upstream behavior as a verified GoreeCloud feature.**
- No GoreeCloud VPN service, native client release, user-facing GoreeCloud UI transformation, or production configuration has been delivered by this import.
- Upstream automation workflows were intentionally **not imported** to avoid accidental upstream publishing, external operations, and secret use. GoreeCloud-specific checks require independent review.

## Documentation

- [Feature status and evidence navigation](docs/FEATURES.md)
- [Proposed product specifications and acceptance criteria](docs/SPECIFICATIONS.md)
- [Planned feature and capability catalog](docs/PLANNED-FEATURES.md)
- [Implemented source-level work (not release claims)](docs/IMPLEMENTED-FEATURES.md)
- [Upstream provenance, modifications, and license obligations](docs/fork-to-native/UPSTREAM.md)
- [Migration and acceptance milestones](docs/fork-to-native/ROADMAP.md)
- [Security baseline and release restrictions](docs/fork-to-native/SECURITY.md)
- [Read-only VPS preflight and controlled NetBird migration gates](docs/fork-to-native/MIGRATION.md)
- [Nine platform-system integration assessment](docs/fork-to-native/INTEGRATIONS.md)
- [Original upstream README, retained for provenance](docs/upstream/NETBIRD_README.md)

## Automatic updates during development

Inherited automatic installers are blocked on every platform until a GoreeCloud-owned signed update chain is qualified. Direct updater calls and management-forced updates cannot enable installation. See the [installer restriction](docs/fork-to-native/SECURITY.md#automatic-installer-restriction-development-only) and release blocker [#32](https://github.com/GoreeCloud/VPN/issues/32).

## Licensing

The imported NetBird repository applies **BSD-3-Clause** to most directories, but **AGPL-3.0** to `management/`, `signal/`, `relay/`, and `combined/`. The root [LICENSE](LICENSE), [LICENSES](LICENSES), component license files, and [AUTHORS](AUTHORS) remain part of this source distribution. Retain applicable copyright, source availability, and other obligations in all future derivatives and distributions.

**Attribution:** GoreeCloud VPN is independent from and is not endorsed by NetBird GmbH. NetBird and WireGuard names and marks are not GoreeCloud trademarks.

## Developer checks

Run `bash scripts/check-ftn-baseline.sh` for source/provenance/license guardrails. Run `go test -count=1 ./base62 ./monotime ./shared/netiputil` with Go 1.27.0 or another compatible, validated toolchain for a **limited Go test baseline**. The scoped GitHub Actions workflow executes these tests on pull requests without invoking inherited upstream release automation.

The `shared/netiputil` serializer now rejects invalid prefixes before serialization; this protection has regression tests for malformed IPv4/IPv6 prefix inputs. The client ACL source-prefix decoder also preserves the encoded subnet masks and `/0` wildcards rather than narrowing policy rules to individual hosts. Run `go test -p 2 -count=1 ./client/internal/acl` to validate that behavior locally; a separate scoped CI job verifies the same ACL package and runs `go vet`.

A separate build-only gate compiles the inherited signal and relay Go entrypoints with `go build -p 2 -buildvcs=false ./signal ./relay`; disabling VCS stamping supports isolated builders without a Git executable. The CI `remaining-go-entrypoints-build` job also compiles inherited `client`, `management`, and `combined` Go entrypoints, so all five primary Linux Go entrypoint packages now have source-compilation evidence. Neither job proves service startup, networking, correct behavior, or a deployable release.

These checks do **not** replace comprehensive cross-platform builds, runtime VPN/firewall integration tests, independent penetration review, GUI acceptance, privacy validation, or release certification. Do not use this repository as a deployable VPN without completing the required tests and review.


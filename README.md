# GoreeCloud VPN

**Development status: Fork-to-Native foundation. Not a validated or released GoreeCloud VPN product.**

GoreeCloud VPN is a planned GoreeCloud-native, privacy-conscious VPN and private-networking product. This repository contains a **source snapshot from [NetBird](https://github.com/netbirdio/netbird)** as the initial engineering foundation. Its inherited components are not yet a standalone, independently rebranded, tested, or production-ready GoreeCloud implementation.

## Current scope

- Inherited upstream networking implementation includes WireGuard-based private networking, peer connectivity, and infrastructure components.
- The original Go module path and many upstream product identifiers remain intact during the audited import stage. **Do not interpret inherited upstream behavior as a verified GoreeCloud feature.**
- No GoreeCloud VPN service, native client release, user-facing Glaze transformation, or production configuration has been delivered by this import.
- Upstream automation workflows were intentionally **not imported** to avoid accidental upstream publishing, external operations, and secret use. GoreeCloud-specific checks require independent review.

## Documentation

- [Upstream provenance, modifications, and license obligations](docs/fork-to-native/UPSTREAM.md)
- [Migration and acceptance milestones](docs/fork-to-native/ROADMAP.md)
- [Security baseline and release restrictions](docs/fork-to-native/SECURITY.md)
- [Nine platform-system integration assessment](docs/fork-to-native/INTEGRATIONS.md)
- [Original upstream README, retained for provenance](docs/upstream/NETBIRD_README.md)

## Licensing

The imported NetBird repository applies **BSD-3-Clause** to most directories, but **AGPL-3.0** to `management/`, `signal/`, `relay/`, and `combined/`. The root [LICENSE](LICENSE), [LICENSES](LICENSES), component license files, and [AUTHORS](AUTHORS) remain part of this source distribution. Retain applicable copyright, source availability, and other obligations in all future derivatives and distributions.

**Attribution:** GoreeCloud VPN is independent from and is not endorsed by NetBird GmbH. NetBird and WireGuard names and marks are not GoreeCloud trademarks.

## Developer checks

Run `bash scripts/check-ftn-baseline.sh` for source/provenance/license guardrails. Run `go test -count=1 ./base62 ./monotime ./shared/netiputil` with Go 1.27.0 or another compatible, validated toolchain for a **limited Go test baseline**. The scoped GitHub Actions workflow executes these tests on pull requests without invoking inherited upstream release automation.

The `shared/netiputil` serializer now rejects invalid prefixes before serialization; this protection has regression tests for malformed IPv4/IPv6 prefix inputs. These checks do **not** replace full Go compilation, integration tests, independent penetration review, GUI acceptance, privacy validation, or release certification. Do not use this repository as a deployable VPN without completing the required tests and review.


# GoreeCloud VPN — Implemented Features (Source-Level Evidence)

> **Scope:** Verified repository evidence and scoped test history, **not** delivered GoreeCloud VPN product features. Baseline documentation review: 2026-10-16. Targeted update-policy evidence added: 2026-10-21.

The current repository is an imported NetBird source foundation undergoing Fork-to-Native conversion. Its inherited functionality must not be represented as a verified, separately branded, released or production-ready GoreeCloud application.

## Repository-recorded source work

| Evidence identifier | Current evidence | Scope and limitations |
| --- | --- | --- |
| M0 — provenance | GoreeCloud/VPN source snapshot and upstream provenance recorded; licenses and inherited notice files preserved | Fork-to-Native foundation; independent native implementation unverified |
| M0 — workflow isolation | Upstream GitHub workflow automation intentionally excluded; scope-limited source guardrails added | Does not verify every inherited endpoint or future workflow |
| M0 — limited tests | Repo reports portable Go tests for `base62`, `monotime` and `shared/netiputil`, including invalid-prefix regression coverage | Scoped tests only; not full product build or network verification |
| M0 — scoped builds | GitHub CI run [38888371667](https://github.com/GoreeCloud/VPN/actions/runs/38888371667) passed Go 1.27 source compilation of five inherited Linux entrypoints: `client`, `management`, `combined`, `signal`, `relay` | Compilation does not establish service startup, networking, cross-platform artifacts, security, correctness or deployability |
| M1 — ACL decoding | Repo reports ACL source-prefix decoder changes preserving IPv4/IPv6 CIDR and `/0` wildcards, with scoped regression tests | Runtime control-plane propagation, real firewall application and revocation remain unverified |
| M1 — automatic installer restriction | [PR #39](https://github.com/GoreeCloud/VPN/pull/39) blocks both daemon and detached updater entry points before side effects; all 21 checks passed, including native Linux/Windows/macOS rejection tests with production and development signing tags | Preventive development guard; owned signing roots, package identity, signed upgrades and rollback remain unqualified (#32) |
| M1 — version-discovery privacy and lifecycle | [PR #40](https://github.com/GoreeCloud/VPN/pull/40) removes the inherited default endpoint, cancels and waits for in-flight fetches, prevents duplicate/late startup, and bounds request time and streamed response size; scoped race tests and CI passed | No discovery service or signed update channel is enabled; no product-wide endpoint or runtime privacy certification |

These entries map to the existing M0/M1 milestones in [Fork-to-Native roadmap](fork-to-native/ROADMAP.md), [Security baseline](fork-to-native/SECURITY.md) and [README](../README.md). The review establishes that these claims exist in current repository records, **not** that all tests were independently rerun in this documentation-only change.

## Not established by current evidence

No independently verified GoreeCloud VPN native client release, hosted service, production network, platform-system integration, secure internet exit, privacy/no-logs claim, obfuscated transport, full VPN acceptance suite, signed package or Stable lifecycle exists in the evidence reviewed.

All such targets belong in [Planned Features](PLANNED-FEATURES.md) until independently implemented and verified. Release acceptance and source-level implementation are different lifecycle states.

## Promotion rule

An entry can be promoted as a **GoreeCloud VPN implemented capability** only when linked to an exact source revision and reproducible, relevant tests, with documented supported platforms, security/privacy boundaries and runtime verification. Deployment, general availability and certification require separate evidence.

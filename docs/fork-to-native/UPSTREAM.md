# Upstream source provenance

- **Product:** GoreeCloud VPN
- **Destination:** `GoreeCloud/VPN` — independent, GoreeCloud-controlled original repository
- **Development approach:** Fork-to-Native; **not** complete Native
- **Upstream:** `https://github.com/netbirdio/netbird`
- **Source branch:** `main`
- **Imported upstream commit:** `8c70f9ec71e2a3b4ed01e8776a6a78b1f5a8118c`
- **Acquisition date:** 2026-10-12
- **Import method:** shallow upstream source checkout copied into the existing GoreeCloud repository on a development branch; original GoreeCloud commit history preserved. Upstream Git ancestry was **not** imported; the exact source revision is recorded above.

## Deliberate initial differences

1. The pre-existing GoreeCloud placeholder README was replaced with a truthful GoreeCloud development README. Its history remains available in Git.
2. The original upstream `README.md` was retained verbatim at `docs/upstream/NETBIRD_README.md`.
3. Upstream `.github/workflows/*` automation was excluded; none of its upstream release, publish, sync, or credential-bearing workflows may be executed as GoreeCloud workflows without an individual audit.
4. Replaced upstream support, security reporting, and contribution entry points with truthful GoreeCloud development-stage guidance; preserved original documents under docs/upstream.
5. Excluded upstream GitHub repository automation and promotional configuration (including FUNDING, Dependabot, issue/discussion templates, contributor bots, Crowdin and funding.json); do not restore before security review.
6. Added GoreeCloud process, security, and integration documents and narrowly scoped baseline checks.
7. Otherwise, the imported source is an upstream snapshot, **not** a completed product-level transformation.

The original `go.mod` module path is intentionally retained pending audited dependency, import-path, ABI, release, and build migration. Uncontrolled global text replacement could break networking and external integrations.

## License and trademark obligations

The root `LICENSE` specifies BSD-3-Clause for most sources and AGPL-3.0 for `management/`, `signal/`, `relay/`, and `combined/`. The root `LICENSES/` contains authoritative license texts; each of those four component directories also includes a `LICENSE` file. Preserve all required original copyright/license notices and meet corresponding source-distribution and network-service obligations before deployment or release. Conduct a legal/compliance review for AGPL-covered service modifications before any public hosted operation.

NetBird and WireGuard trademarks are not licensed as GoreeCloud product identity. Remove upstream-branded user-facing presentation during approved transformation while retaining legally required notices and technical references where necessary. Do not imply endorsement by NetBird, its contributors, or the WireGuard project.

## Upstream maintenance

Review security advisories, upstream changes, dependency updates and fixes individually. Only cherry-pick/import vetted changes after compatibility, license, privacy, security, and regression checks. Do not configure automatic upstream-to-GoreeCloud merges.

**Upstream does not govern GoreeCloud releases.** No imported application functionality has been runtime-verified as a GoreeCloud release.


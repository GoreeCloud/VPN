# GoreeCloud VPN update-channel and installer safety

**Release gate: NOT APPROVED.** The source may compile, but no signed GoreeCloud VPN installer or end-to-end update lifecycle has been validated.

## Verified limited safeguard

The manual client download link provided by the common version package now resolves to the GoreeCloud-owned [releases inventory](https://github.com/GoreeCloud/VPN/releases) across Windows, macOS and Linux, rather than NetBird commercial download hosts. This page is a discovery link and does **not** prove that a safe or compatible GoreeCloud binary exists. Tests assert that the inherited installer origins are not used by these platform helpers.

## Remaining release blockers

- Legacy automatic updater code and package installation flows still contain inherited download origins; they are **not** authorized for GoreeCloud release channels. In particular the updater signing-key URL in `client/internal/updater/installer/repourl_prod.go` still points to upstream infrastructure.
- Build reproducible native installers for supported platforms, review supply-chain licensing, generate provenance and signed attestations, and establish GoreeCloud-owned trust anchors and revocation.
- Test explicit update consent, upgrade/downgrade, rollback, anti-downgrade, key rotation and offline failure conditions without modifying production NetBird.
- Ensure desktop/tray 'update' actions cannot trigger an unverified package or confuse users with an installation from the upstream NetBird distribution.
- **Do not deploy, publish binaries or change operating VPN services** merely because this manual-link correction passes CI.

Related: [release readiness](https://github.com/GoreeCloud/VPN/issues/2) and [upstream endpoint audit](https://github.com/GoreeCloud/VPN/issues/5).

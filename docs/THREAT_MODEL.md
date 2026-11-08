# GoreeCloud VPN — Threat Model

Status: Preliminary design review, November 3, 2026. No production security certification is claimed.

## Trust boundaries

- Devices and public keys remain untrusted until authenticated enrollment and approval.
- Administrators control management state, not live traffic, in this alpha.
- Future privileged network agents must validate changes and apply default-deny packet rules.
- Routing, DNS, relays, gateways and file access require independent authorization.
- GoreeCloud Mesh owns cross-product orchestration; GoreeCloud UI owns visual design.

## Required release evidence

1. Verified device identity and possession of endpoint-held cryptographic keys.
2. Real WireGuard tunnel establishment and revocation tests on isolated hosts.
3. Source, destination, protocol and port restrictions enforced on packets, not just API decisions.
4. Protected coordination transport, audited scoped identities and recovery procedures.
5. DNS and route leak testing, network interruption and relay failure simulations.
6. Independent security review and explicit authorization before production rollout.

## Current boundary

A disposable rootless Linux lab now demonstrates real WireGuard kernel encryption, test-only guarded nftables rule application and peer-key removal (see [isolated lab](ISOLATED_WIREGUARD_LAB.md)), but **GoreeCloud VPN has not implemented the privileged agent, authenticated network policy distribution or automated data-plane enforcement**. The peer planner and generated stanzas remain offline previews only. An experimental nftables ingress policy preview is also read-only and requires an independently reviewed agent and atomic fail-closed update strategy; the optional rootless lab applies its text manually, not through GoreeCloud VPN. WireGuard peer AllowedIPs do not enforce port-level policies. The repository does not modify any live VPN, router or VPS, and local event history is not tamper-proof.

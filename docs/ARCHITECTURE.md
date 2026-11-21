# GoreeCloud VPN — independent first-party architecture

GoreeCloud VPN is an original native VPN product, **not NetBird**, not a NetBird fork, and not the live NetBird deployment. Source authority is [GoreeCloud/VPN](https://github.com/GoreeCloud/VPN). Third-party NetBird operations have separate ownership in [GoreeCloud Mesh](https://github.com/GoreeCloud/mesh).

## Implemented: isolated control-plane preview

- `cmd/vpnd`: HTTP JSON API, loopback by default; TLS certificate **mandatory** when binding an external address, no external HTTP/plaintext listener.
- `internal/control`: concurrency-safe, owner-private JSON peer registry, unique /32 address reservations in a development-only 10.77.0.0/24 range, revocation tombstones, no key escrow.
- `internal/credentials`: CSPRNG administrator-token creation and strict private-file read; no default credentials, no token in URL, no secrets in public source.
- `internal/api`: constant-time hash comparison for bearer token, bounded strict JSON input, secure response headers, fail-closed unknown routes, immutable public-health check, protected peer CRUD.
- `cmd/vpnctl`: private local WireGuard-compatible X25519 key generation and strict 0600 split-tunnel client config export; no server-side private key creation; administrative CLI for local HTTPS/loopback peer registry and revocation. The configuration exporter does not activate tunnels.
- `web/`: responsive same-origin console, in-memory token, registered identities, explicit confirmation for revoke; no token storage.
- `desktop/linux/`: native Qt Quick 6.12.0 client surface for local/HTTPS control-plane viewing, not Electron.
- `android/`: native Kotlin Compose Material 3 (Expressive-compatible Android foundation), HTTPS-only control-plane peer list; token only in Activity memory, cleared on backgrounding. It is not a VpnService implementation.

These components are **not** sufficient to create a VPN tunnel. Registration of a public key does not push a WireGuard peer, exchange keys with a gateway, apply routes, or establish encrypted connectivity. The API `/v1/info` explicitly returns `tunnel_operational:false`.

## Proposed: functioning data plane (not implemented)

A production WireGuard-based tunnel design will require a separately authorized VPN gateway and agent that verify peer identity, securely reconcile public-key changes, install/enforce WireGuard configuration, manage endpoints and rekey/expiry, transport NAT traversal or relay, handle IPv4/IPv6 routes, provide split and full tunnel semantics with DNS leak protection and a kill switch, and protect policy/failure modes. Linux should use kernel WireGuard with a tightly scoped privileged agent, not run the entire web server as root. Android requires an explicit VpnService permission flow and an audited userspace WireGuard implementation with privacy-safe lifecycle; no VpnService has been added to this app.

Do **not** construct all-to-all access automatically from registered peers; the eventual authorization model needs GoreeCloud Identity scopes and Wardveil-enforced least privilege. GoreeShield controls telemetry, logs and peer metadata consent; Mesh integration remains opt-in and distinct. Avoid reuse of the currently running NetBird peer keys, setup keys or PAT.

## UI authority and status

GoreeCloud UI's verified central source is [GoreeCloud/gc-ui](https://github.com/GoreeCloud/gc-ui), with a provisional alpha Compose Material 3 Expressive adapter and Compose Multiplatform module. This repository uses platform-native default controls **without inventing brand colors** until the source-based central adapter and verified design tokens are integrated and compiled as a first-party consumer. No stable GoreeCloud UI package or user-accepted visual release is presumed. Linux desktop primary UI is Qt Quick 6.12, not Compose Multiplatform (which may later share non-visual state). A web foundation migration to canonical GC UI React/Next components requires a separate verified build and test.

## Security and release gates

1. **Control-plane source:** race-enabled Go tests, vet, build, strict auth, payload rejection, private-file modes and isolated localhost E2E.
2. **Cryptographic interface:** independent WireGuard crypto/public-key compatibility tests, no private-key disclosure, key rotation/revocation across durable restarts.
3. **Tunnel acceptance:** real two-peer handshakes, invalid peer denial, NAT/relay recovery, routing conflicts, split/full tunnel DNS leak checks, disconnect/kill-switch and power-cycle tests.
4. **Native clients:** compile and device/emulator runtime on Android, Qt 6.12 Linux compile and hardware acceptance, mobile background restrictions and accessibility.
5. **MIPS:** enforce GoreeCloud Identity, GoreeShield, Wardveil and Mesh contracts with evaluated GoreeCloud UI. No MIPS is considered integrated merely because this document names it.
6. **Release:** CI green, license audit, threat review, secure update/signing, restore rehearsal, load/performance checks and explicit release candidate promotion.

## Deployment boundary

Do not deploy this control-plane preview onto the live NetBird VPS host, repoint `netbird.goreecloud.com`, or modify the existing Caddy/AdGuard configuration without a separate migration plan and verified rollback. The current preview runs on isolated developer loopback and **is not deployed**.

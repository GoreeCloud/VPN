# GoreeCloud VPN — independent first-party architecture

GoreeCloud VPN is an original native VPN product, **not NetBird**, not a NetBird fork, and not the live NetBird deployment. Source authority is [GoreeCloud/VPN](https://github.com/GoreeCloud/VPN). Third-party NetBird operations have separate ownership in [GoreeCloud Mesh](https://github.com/GoreeCloud/mesh).

## Implemented: isolated control-plane preview

- `cmd/vpnd`: HTTP JSON API, loopback by default; TLS certificate **mandatory** when binding an external address, no external HTTP/plaintext listener.
- `internal/control`: concurrency-safe, owner-private JSON peer registry, unique /32 address reservations in a development-only 10.77.0.0/24 range, separate explicit administrator approval, revocation tombstones, exclusive state lock and fail-closed stored-registry validation, no key escrow.
- `internal/credentials`: CSPRNG administrator-token creation and strict private-file read; no default credentials, no token in URL, no secrets in public source.
- `internal/api`: constant-time hash comparison for bearer token, bounded strict JSON input, secure response headers, fail-closed unknown routes, immutable public-health check, protected peer CRUD.
- `cmd/vpnctl`: private local WireGuard-compatible X25519 key generation and strict 0600 split-tunnel client config export; no server-side private key creation; administrative CLI for local HTTPS/loopback peer registry and revocation. The configuration exporter does not activate tunnels.
- `web/`: React 19/Vite same-origin compiled console, in-memory token, registered identities, explicit confirmation for revoke; no token storage.
- `desktop/linux/`: native Qt Quick 6.12.0 client surface for local/HTTPS control-plane viewing, not Electron.
- `android/`: native Kotlin Compose Material 3 (Expressive-compatible Android foundation), HTTPS-only control-plane inventory viewer and separate opt-in local WireGuard GoBackend tunnel with Android VpnService consent. Admin token is cleared on backgrounding; the imported tunnel configuration remains in process memory. Runtime acceptance is pending.

The control plane alone is **not** sufficient to create a VPN tunnel. Registration of a public key does not push a WireGuard peer, exchange keys with a gateway, apply routes, or establish encrypted connectivity. The API `/v1/info` explicitly returns `tunnel_operational:false`.

## Linux kernel agent — gated development source, not deployed

An optional **Linux-only** `cmd/vpnagent` now models and can explicitly reconcile a fixed `gcvpn0` WireGuard kernel interface for the private development `10.77.0.0/24` split route. It invokes the verified `ip` and `wg` tools as discrete subprocesses, **never a shell or wg-quick PostUp/PostDown hook**. Private keys are supplied to `wg set` via an absolute 0600 key-file path rather than command arguments. The planning operation prints only public endpoint, route and key-path metadata.

The apply path requires Linux root/CAP_NET_ADMIN context **and** two independent flags (`--confirm-apply`, `--acknowledge-network-impact`); it refuses an existing `gcvpn0` interface or overlapping route. On partial failure it removes only the newly created interface. Success writes a private ownership marker; stopping requires separate confirmation and a verified WireGuard interface. The agent is **not deployed** and **must only be run on an authorized isolated test network** after verifying the actual gateway, key materials, host routing, firewall controls and rollback; it does **not** configure a gateway or prove successful transport.

Official command API syntax was cross-checked with [WireGuard quick start](https://www.wireguard.com/quickstart/) and [wg(8)](https://www.man7.org/linux/man-pages/man8/wg.8.html). The agent requires external `iproute2`, `wireguard-tools` and Linux kernel WireGuard support. Pure plan and rollback tests run in CI without root or any live host network action. A real isolated multi-peer handshake remains an unsatisfied release gate.

## Proposed: functioning data plane (not implemented)

A production WireGuard-based tunnel design will require a separately authorized VPN gateway and agent that verify peer identity, securely reconcile public-key changes, install/enforce WireGuard configuration, manage endpoints and rekey/expiry, transport NAT traversal or relay, handle IPv4/IPv6 routes, provide split and full tunnel semantics with DNS leak protection and a kill switch, and protect policy/failure modes. Linux should use kernel WireGuard with a tightly scoped privileged agent, not run the entire web server as root. Android now includes an explicit VpnService permission flow and upstream WireGuard GoBackend. Native build, consent, live handshake and privacy-safe lifecycle require independent validation.

Do **not** construct all-to-all access automatically from registered peers; the eventual authorization model needs GoreeCloud Identity scopes and Wardveil-enforced least privilege. GoreeShield controls telemetry, logs and peer metadata consent; Mesh integration remains opt-in and distinct. Avoid reuse of the currently running NetBird peer keys, setup keys or PAT.

## UI authority and status

GoreeCloud UI's verified central source is [GoreeCloud/gc-ui](https://github.com/GoreeCloud/gc-ui), with a provisional alpha Compose Material 3 Expressive adapter and Compose Multiplatform module. The React web and Android preview use GoreeCloud UI Lagoon alpha values from the canonical design token source. The separate source adapters are not yet consumed, and this is not founder visual acceptance. No stable GoreeCloud UI package or user-accepted visual release is presumed. Linux desktop primary UI is Qt Quick 6.12, not Compose Multiplatform (which may later share non-visual state). An original React/Vite conversion now passes local TypeScript, build and localhost asset/JSON tests; independent browser and accessibility acceptance remain open.

## Security and release gates

1. **Control-plane source:** race-enabled Go tests, vet, build, strict auth, payload rejection, private-file modes and isolated localhost E2E.
2. **Cryptographic interface:** independent WireGuard crypto/public-key compatibility tests, no private-key disclosure, key rotation/revocation across durable restarts.
3. **Tunnel acceptance:** real two-peer handshakes, invalid peer denial, NAT/relay recovery, routing conflicts, split/full tunnel DNS leak checks, disconnect/kill-switch and power-cycle tests.
4. **Native clients:** compile and device/emulator runtime on Android, Qt 6.12 Linux compile and hardware acceptance, mobile background restrictions and accessibility.
5. **MIPS:** enforce GoreeCloud Identity, GoreeShield, Wardveil and Mesh contracts with evaluated GoreeCloud UI. No MIPS is considered integrated merely because this document names it.
6. **Release:** CI green, license audit, threat review, secure update/signing, restore rehearsal, load/performance checks and explicit release candidate promotion.

## Deployment boundary

Do not deploy this control-plane preview onto the live NetBird VPS host, repoint `netbird.goreecloud.com`, or modify the existing Caddy/AdGuard configuration without a separate migration plan and verified rollback. The current preview runs on isolated developer loopback and **is not deployed**.

## Development gateway renderer (source-only)

The first-party `internal/wireguard/gateway.go` renderer and `vpnctl config-gateway` command produce local mode-0600 WireGuard gateway configuration from a private gateway key and explicit verified peer public keys with unique `/32` assignments. The gateway address is fixed to 10.77.0.1/24, and individual peers receive only their exact /32 AllowedIPs. Duplicate peers, oversized lists, out-of-subnet addresses and overbroad defaults are rejected. This is not a configured or deployed gateway: IP forwarding, firewall, NAT, host interface setup, and an actual handshake all require independent acceptance.


## Static React build and Android data-plane ownership

The web React app compiles with Vite into web/dist; vpnd serves only the compiled index and /assets/ directory, with management requests protected by explicit bearer authorization. No token is persisted to web storage. Android imports a user-reviewed WireGuard config via the Android system picker and requests OS VPN permission only on user-initiated Connect. Android GoBackend provides encrypted transport; the management API never receives a private key or reports an active tunnel. No real two-device handshake was demonstrated in this source change.


## Registry-to-gateway snapshot (offline and revocation-sensitive)

vpnctl export-peers authenticates to the first-party control-plane API, verifies the bounded complete response and fails on duplicate IDs, addresses, keys or invalid /32s. It writes a new private mode-0600 JSON snapshot containing only **explicitly approved, non-revoked** public keys and assigned peer addresses, for subsequent reviewed config-gateway rendering. Neither action changes active kernel WireGuard or firewall state. Revocation becomes packet-enforced only after an independent, authorized gateway apply and real traffic-denial test. Manually crafted --peers-file exports remain supported but must not be confused with the current registry.


## Disposable kernel namespace lab (CI-only)

The optional scripts/wireguard-netns-smoke.sh refuses non-GoreeCloud hosted GitHub Actions Linux execution and requires root only inside an ephemeral runner. It uses two isolated network namespaces and a synthetic veth underlay. GoreeCloud's actual compiled vpnd/vpnctl generates and exports reviewed development peer configs, upstream wg-quick provides the kernel encrypted transport, and wg syncconf explicitly applies the post-revoke gateway state. It asserts both a successful cryptographic handshake and negative peer traffic after applied revocation. Host routes, DNS, firewall and actual devices are not touched. A passing synthetic lab does not certify an authorized real remote-access overlay or physical Android/Linux clients.


## Default-deny device admission

Registration never grants an identity eligibility for gateway configuration. The Go peer registry records ApprovedAt only after a separately authenticated POST /v1/peers/{id}/approve admin action. The guarded CLI command vpnctl approve --id ID --confirm and the React console expose that action. Duplicate approvals and any attempt to reapprove a revoked identity return conflict. A gateway snapshot contains only ApprovedAt != nil AND RevokedAt == nil, while retaining tombstones for audit. Prior saved peer records lacking ApprovedAt stay pending (no implicit mass approval).

One active process holds a Linux advisory flock on a 0600 file in the 0700 state directory before loading registry JSON. A concurrent daemon fails startup. The state loader validates peer ID, /32 address, canonical public key, distinct identity/address and consistent approval/revocation times; corrupted state fails closed and releases the lock. This is not a substitute for authenticated device owner verification, per-service packet-level ACLs, OIDC/RBAC, or automatic gateway convergence.


## Offline, deny-by-default gateway-local ACL

A separate internal/policy module now renders a deterministic nftables inet table for the dedicated development interface named gateway, using a reviewed array of explicitly approved peer public keys and /32s. Each opt-in grant binds one of those keys (through its WireGuard AllowedIPs-verified /32 source) to a specified gateway-local TCP/UDP port or to ICMP echo requests. Rules are installed only in the INPUT chain after explicit review; all remaining traffic entering from that interface is dropped. A FORWARD-chain drop prevents a gateway from silently becoming a route into unrelated LAN peers or external subnets. Existing host interface traffic is not targeted.

vpnctl config-acl creates a new mode-0600 output from validated, private input files and requires --confirm. It intentionally never invokes nft or performs a live host change. The GitHub Actions netns test exercises nftables in a disposable namespace: even a cryptographically authenticated peer is denied before the service allowance, then permitted after an explicit reviewed rule-set replacement; revoked and unknown identities fail closed. Real deployment needs atomic rollback-safe rule application, Identity-scoped grants, owner consent, restoration on restart and production change control. Do not treat source generation or CI as a production Wardveil deployment.

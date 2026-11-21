# GoreeCloud VPN

**GoreeCloud VPN is an original, first-party GoreeCloud networking product. It is not NetBird.** NetBird is a separate third-party VPN service currently deployed on the founder's VPS, with operator integration source under [GoreeCloud Mesh](https://github.com/GoreeCloud/mesh). No NetBird server, CLI, product code or credentials belong in this repository.

## Development checkpoint

**0.2.0 development source preview; Android tunnel source exists, but end-to-end VPN connectivity and production readiness are unverified.**

This branch contains a functional, authenticated **peer registry with separate admin approval and revocation, and administrator CLI**, including non-activating WireGuard client and gateway configuration generators written in Go, plus development-stage **web**, **native Linux Qt Quick 6.12**, and **native Android Compose Material 3** client surfaces. The API does **not** configure WireGuard, create encrypted tunnels, alter routes or host firewalls, relay traffic, control VPN DNS, or remotely provision Android VPN permission. Android separately requests OS VPN consent on demand. A registered peer is only an identity record. The authenticated `GET /v1/info` response explicitly returns `"tunnel_operational":false`.

| Component | Implemented source | Verified acceptance |
| --- | --- | --- |
| Backend `cmd/vpnd` | Go standard-library REST control plane, localhost default, TLS mandatory on non-loopback, bounded auth/JSON, private atomic state | Go race tests, vet, local build, isolated local API lifecycle and restart |
| `cmd/vpnctl` | CSPRNG admin token creation, local X25519/WireGuard-compatible keys, mode-0600 split-tunnel config export, admin peer registration, explicit approval, revocation and eligible gateway snapshot export commands | Go tests and disposable localhost E2E, including client/gateway config exports and approval/revocation-filtered snapshots |
| Web `web/` | React 19/Vite compiled same-origin identity console, in-memory token and verified GoreeCloud UI Lagoon alpha colors | Local TypeScript/build and localhost compiled asset/JSON E2E passed; browser UX still unverified |
| Linux `desktop/linux/` | Native Qt Quick 6.12 graphical registry client | Source contracts; native Qt 6.12 build/hardware QA pending |
| Android `android/` | Native Compose Material 3 admin viewer and opt-in WireGuard GoBackend with local config import and Android VpnService consent | [Earlier viewer APK CI passed](https://github.com/GoreeCloud/VPN/actions/runs/44875185791); no emulator/phone runtime acceptance |
| Linux WireGuard agent | Separate root-gated `cmd/vpnagent` with fixed `gcvpn0`, split-only route, and rollback | Go unit/plan tests only; no privileged execution or real handshake |
| Actual encrypted tunnel | **Not running or accepted** | Gateway setup, agent installation and real two-peer handshake pending |

The first-party client apps are independent of NetBird; do not confuse source readiness with a VPN that carries traffic.


**Verified CI checkpoint (November 20, 2026):** [First-party control-plane source safety](https://github.com/GoreeCloud/VPN/actions/runs/44875185778) and [Android native Compose APK build](https://github.com/GoreeCloud/VPN/actions/runs/44875185791) both passed on the reviewed first-party feature branch. The Android workflow verifies a compiled debug APK exists on its temporary runner; it does not publish an installable user release. The authorized laptop's earlier offline Android packaging attempts timed out due to resource pressure; only the hosted compile is accepted. No physical phone/emulator or Qt6.12 Linux executable was exercised.

## Build and test the control plane

Requires Go 1.24+, Python 3 for source contract tests, and Node.js 22+ with npm for the React build. Build without root and use local private directories:

```bash
go test -race ./...
go vet ./...
python3 scripts/check_source_contracts.py
cd web && npm ci && npm run typecheck && npm run build && cd ..
bash scripts/e2e-loopback.sh
go build -o ./build/vpnd ./cmd/vpnd
go build -o ./build/vpnctl ./cmd/vpnctl
```

For a **separate developer-only localhost instance** (not NetBird), create private credentials and keys:

```bash
./build/vpnctl init-admin --token-file "$HOME/.config/goreecloud/vpn/admin-token"
./build/vpnctl keygen --dir "$HOME/.local/share/goreecloud/vpn/my-device"
./build/vpnd --listen 127.0.0.1:8788 --web-root ./web/dist \
  --state-dir "$HOME/.local/share/goreecloud/vpn/control" \
  --token-file "$HOME/.config/goreecloud/vpn/admin-token"
```

In a second terminal, authenticated peer-registry operations:

```bash
./build/vpnctl info
./build/vpnctl list
./build/vpnctl register --name my-device --confirm \
  --public-key-file "$HOME/.local/share/goreecloud/vpn/my-device/wg-public.key"
```

Open `http://127.0.0.1:8788/` from the development device to try the same-origin web UI, with the private admin token only when using a trusted local browser. Never paste private tokens into GitHub, logs, tickets or this chat. The API client enforces HTTPS for any non-loopback origin; no external listener operates without a configured TLS certificate and key.

## Native apps

**Linux:** open `desktop/linux/` with CMake and **Qt 6.12.0 Qt Quick** installed, then build and run the `goreecloud-vpn-linux` target. No Electron/web wrapper. Qt version/hardware acceptance remain separate from Go testing.

**Android:** open `android/` in Android Studio with the declared AGP 9/Kotlin Compose compiler and Android SDK 37.1; build `:app:assembleDebug`. The native app now contains an opt-in local WireGuard tunnel through official Android GoBackend and user-initiated VpnService consent. Live handshake and device acceptance remain unverified. Material 3 is the mandatory expressive foundation. [GoreeCloud UI](https://github.com/GoreeCloud/gc-ui) holds the authoritative central alpha design tokens and Android Compose adapter; direct source-based adapter consumption and runtime visual acceptance are pending, and no brand palette is invented locally.

## Source architecture, security, governance

- [Technical architecture and actual vs planned implementation](docs/ARCHITECTURE.md)
- [Security, privacy, and threat boundaries](docs/SECURITY.md)
- [First-party CLI command reference](docs/CLI_COMMANDS.md)
- [Dedicated first-party CI](.github/workflows/vpn-control-ci.yml)

GoreeCloud Identity, GoreeShield, Wardveil, GoreeCloud Mesh, and GoreeCloud UI remain separate mandatory systems. Their **enforcement** requires later tested integration; mentioning them is not evidence of adoption. The current Go server uses a private administrator bearer token for development only, not a complete production identity platform.

## Remaining product work

Independently validate the Linux agent and Android VpnService/GoBackend with a genuine encrypted two-peer tunnel, identity-scoped access policies, split/full tunnel configuration, NAT traversal and relays, IPv6, DNS-leak protection, device revocation propagation, key rotation, fail-safe disconnect, platform-native UX, signed releases and live two-peer connection acceptance. The project must never reuse or alter the existing third-party NetBird credentials, API tokens, tunnel keys, Docker containers, or production DNS.

## License

Original GoreeCloud-controlled source in this repository is available under the [Apache License 2.0](LICENSE); third-party SDKs and protocols retain their own licensing and trademark rights. No NetBird source has been included.


## Source-build acceptance boundaries

Build the React application into web/dist before starting vpnd with that directory as web-root. The Go handler serves only the compiled entrypoint and assets, not source files. Native Qt Quick 6.12 is checked by a separate hosted compilation job; Android GoBackend compilation and physical-device consent tests are independent acceptance gates. No live VPS or NetBird systems are modified by these source builds.

The Android debug build uses a separate application ID suffix (.dev) so that temporary physical-device QA does not replace an installed GoreeCloud VPN application. Hosted CI stores an unsigned-for-production, debug-signed development APK only as a short-lived Actions testing artifact; it is not a release or distribution channel.


## Isolated WireGuard integration test

The optional GitHub-hosted kernel namespace workflow builds vpnd/vpnctl and exercises a complete development-only chain: register peer public key, export active gateway policy, generate client/gateway configs, establish an encrypted WireGuard handshake between disposable network namespaces, then revoke the record, apply the new gateway config and verify packets are denied. It runs only on an explicitly gated root-capable GoreeCloud GitHub Actions ephemeral Linux runner, never on the live VPS or laptop host namespace. A successful result is a synthetic two-namespace tunnel, not actual Android/Linux client device acceptance, NAT traversal, relay, Identity, DNS/IPv6 or production policy verification.


## Explicit device approval and state ownership

New device registrations are **pending and ineligible for gateway export** until an administrator explicitly verifies the public key and approves the peer using the guarded web console or vpnctl approve --id VERIFIED_ID --confirm. Approval never activates networking. Only **approved AND non-revoked** peer identities appear in subsequent vpnctl export-peers snapshots; the reviewed config must still be separately applied at the gateway. Revoked identities cannot be reapproved; enroll a different newly generated key after a manual owner review. Existing unapproved records remain pending after upgrades by design.

The Go peer registry now uses an exclusive nonblocking private OS file lock to prevent two daemons from overwriting each other's state; start one instance per state directory. Startup validates persisted IDs, unique /32 allocations, public keys, approval/revocation chronology and file modes before serving API traffic. The daemon closes its lock on normal shutdown and the OS releases it on process termination. It does not contain WireGuard private keys.


The native Qt CI now includes an offscreen QML engine start-and-exit smoke test with a special --smoke-test argument. It does not contact the management API, create tunnel interfaces, or exercise real Linux desktop interaction; physical Linux packaging and input/runtime acceptance remain pending.


## Reviewed gateway-local access policies (new development source)

The offline vpnctl config-acl command produces a private, mode-0600, no-overwrite nftables ruleset from a reviewed approved-peers snapshot and an explicit service-grant JSON file. Each grant binds one approved WireGuard public key to a **gateway-local** TCP/UDP port or ICMP echo request. Unapproved keys, unknown protocols, duplicate grants, wildcard/overbroad addresses and non-private inputs fail closed. The generated firewall defaults to **deny gateway input and forwarded traffic from the dedicated VPN interface** while preserving unrelated host interfaces.

No firewall rules are applied by the CLI. The isolated CI test exercises the generated rules only inside its disposable gateway network namespace, proving an authenticated WireGuard peer cannot ping a gateway service until a separate explicit ICMP allowance is installed. This is NOT yet production Identity/RBAC, per-user resource grants, an automatically reconciled nftables service, audited policy deployment or unrestricted LAN access.


## Encrypted registry backup and staging-only recovery

The developer CLI now supports independently generated owner-private **AES-256-GCM** encrypted snapshots of the peer registry, using only Go's standard-library crypto. A separate random 256-bit backup key is required and must be retained securely outside the backup media. No WireGuard private key is uploaded or backed up by this feature. Backup output uses a versioned AEAD-authenticated format, nonce randomization, no-overwrite mode-0600 output and a SHA-256 readback. An offline restore refuses an existing destination, verifies authenticity and registry structure before writing, and creates a **new 0700 staging state directory** rather than replacing the live daemon's data.

Tests verify approved/pending identity state survives encrypted recovery and detect wrong keys, malformed metadata, tampering, nonprivate paths and overwrite attempts. This is a developer-stage restore rehearsal, not a backup of private tunnel keys, full infrastructure, DNS, OIDC identity, existing NetBird service, or production disaster-recovery certification.


## Development listener, Android import and Linux observer hardening

**Direct HTTP server:** The Go management daemon rejects DNS-rebinding Host values (HTTP 421), cross-origin browser Origin requests (HTTP 403), and cross-site Fetch Metadata requests before accessing the admin API. Its in-memory per-direct-peer request limiter allows a 24-request burst, refilling two requests per second, returning HTTP 429 after exhaustion; it does not trust X-Forwarded-For. With an explicit server certificate/key, the daemon advertises TLS 1.3 as the minimum. Use the exact origin matching --listen: when bound to 127.0.0.1:8788, the browser URL must use 127.0.0.1, not a different Host alias. Tests cover guard rejection, synthetic refill, and real localhost negative requests. This reduces, but does not eliminate, public-exposure risks; Identity authorization, production ingress, rate-limit tuning, audit logging and service ownership remain unimplemented.

**Android:** The official WireGuard GoBackend is retained as a single per-process object through Activity recreation, so the UI can re-query actual local interface state on Resume and retain a disconnect handle. Imported development profiles are denied unless they contain exactly one WireGuard peer, a local 10.77.0.2–254/32 address, and the sole split route 10.77.0.0/24, with optional private 10.77.0.1 DNS. Full-tunnel, arbitrary subnet, external DNS and IPv6 route imports are blocked by policy before WireGuard parses or activates a tunnel. JVM negative/positive tests cover the gate. Config and credentials remain process-memory only. This does **not** establish DNS leak, kill-switch, handshake, Android permission, background service or reboot acceptance.

**Native Linux:** Qt Quick now has an explicit unprivileged, read-only local interface status panel for dedicated gcvpn0. It uses an absolute-path WireGuard CLI with argument-array execution (never a shell or privilege escalation), summarizes whether the most recent local handshake is within 180 seconds without displaying peer identities, and fails closed on malformed data/denied permissions. Its headless Qt CI executes a synthetic handshake-observation self-test and QML startup; no live Linux tunnel or root network changes are performed.


## Preliminary dependency inventory (non-release)

The repository maintains scripts/generate_dependency_inventory.py and standard-library unit tests. It creates an offline, source-derived SPDX 2.3 provisional inventory of npm locked packages, direct Android Gradle library and plugin declarations, native Qt requirements and Go module requirements. CI validates the source-derived inventory and retains the ephemeral JSON report for seven days. Package license conclusions remain explicitly NOASSERTION; the generated list is not complete for transitive Android/Qt native binaries and is not a production signing, legal or vulnerability acceptance gate.

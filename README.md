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

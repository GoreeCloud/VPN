# GoreeCloud VPN

**Status: development preview. Not production-ready, a verified zero-trust overlay, or a tested substitute for NetBird/Twingate.**

GoreeCloud VPN is an open-source, local-first WireGuard networking project consisting of an original management backend, a React web console, a Qt Quick Linux client, and a native Kotlin/Compose Android client.

## Implemented source

| Component | Scope |
| --- | --- |
| [backend/](backend/) | Python standard-library HTTP service on numeric loopback; SQLite public-key peer inventory, bearer auth, revocation marker, offline WireGuard server config renderer |
| [web/](web/) | Next.js/React management console, cookie login, backend-only token bridge, enroll/revoke peer inventory |
| [linux/](linux/) | Native Qt Quick 6.12 desktop UI with explicit polkit permission and system WireGuard connection controls for an administrator-provisioned config |
| [android/](android/) | Kotlin/Material 3 Compose native UI with Android VPN consent and official WireGuard GoBackend tunnel library |
| [docs/](docs/) | Architecture, security, MIPS and operator instructions |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Source/build verification pipeline |

There is NO automatic provisioning, peer-to-peer mesh signaling, NAT traversal, relay, policy enforcement, client config distribution, live network revocation, or public multi-user management in this version. No runtime deployment is configured. Enrollment changes the private inventory; the operator must render, inspect, apply and validate the server configuration independently. UI status is not proof of end-to-end reachability.

## Local management preview

Use a disposable local development host, Python 3.11+ and Node 22+.

1. Generate two different random 32+-character environment secrets locally. Never commit them: GCVPN_ADMIN_TOKEN for the Python API and GCVPN_WEB_ADMIN_TOKEN for the web UI.
2. From the repo root, run Python with PYTHONPATH=backend python3 -m goreevpn serve (backend binds 127.0.0.1:8787).
3. In another terminal run cd web && npm ci && npm run dev (web binds 127.0.0.1:3000).
4. Open http://127.0.0.1:3000 only from the SAME machine, authenticate with the web token, and enroll *WireGuard public keys only*.
5. See [operations](docs/OPERATIONS.md) for private server-key rendering and safe operator application. Never paste peer private keys into the web UI.

### Tests and builds

    PYTHONPATH=backend python3 -m unittest discover -s backend/tests -v
    cd web && npm ci && npm run typecheck && npm run build
    cmake -S linux -B /tmp/gcvpn-qt-build && cmake --build /tmp/gcvpn-qt-build
    cd android && gradle :app:assembleDebug

Linux needs Qt 6.12 and wireguard-tools. Android needs JDK 17+, Android SDK 37.1, Gradle 9.8+ and pinned AGP. These are development builds, not signed/released packages.

## Privacy and security

Private peer keys never enter the management database or web API. The server renderer reads one owner-only server key file and generates a 0600 configuration without applying it. Management binds loopback and requires a separate bearer token; web authentication has HttpOnly SameSite cookies and denies cross-origin mutations. The Android app imports a user-supplied config from the OS picker without persisting it and asks for Android VPN consent before connection. The Linux app operates only a fixed root-owned configuration under explicit polkit authorization. No analytics or telemetry are installed.

This is NOT approved for internet-facing hosting. Identity/OIDC, role-based access, persistent secure sessions, signed builds, independent recovery and other controls require separate acceptance. Read [security](SECURITY.md), [architecture](docs/ARCHITECTURE.md), and [threat model](docs/THREAT_MODEL.md).

## Open source and future development

The original GoreeCloud-authored code in this repo is MIT licensed ([LICENSE](LICENSE)). WireGuard, Qt, React and other dependencies are **separate upstream works** with independent licenses and notices: see [third-party provenance](THIRD_PARTY_NOTICES.md). We did not copy NetBird or Twingate source.

Planned milestones: signed device enrollment, peer discovery/coordination, encrypted two-device tests, ACL enforcement, identity/RBAC, private DNS and subnet routes, NAT traversal and optional self-hosted relay, fail-closed revocation, kill-switch/DNS leak assurance, independent recovery, signed releases, and GoreeCloud MIPS production integration.

# GoreeCloud VPN — architecture and trust boundaries

## Target architecture

1. **Control plane** — device enrollment, identities, permissions, network coordination and state.
2. **Clients and mesh engine** — device-held WireGuard private keys, tunnel interfaces, direct paths, NAT traversal.
3. **Relay and routing engines** — encrypted relay fallback, subnet routing, exit nodes and failover.
4. **Identity and security** — SSO/device identity, verified group membership, real firewall/data-plane enforcement.
5. **Private DNS** — private authoritative records, split DNS, route-based forwarding.
6. **Application gateway** — controlled reverse proxy, service discovery and private/public exposure.
7. **Remote access and transfer** — approved SSH/RDP, privileged sessions, encrypted file exchange.
8. **Monitor and automation** — diagnostics, alerts, audit, APIs, infrastructure, enterprise and AI integrations.
9. **Management console** — GoreeCloud UI design authority, role-specific access and accessibility.

## Current implementation

The Python API is a single-process *management-only* service. A read-only peer planner derives candidate approved-device adjacency from directional allow rules and generates offline WireGuard peer stanzas. These previews do not install interfaces, routes or firewalls, and WireGuard AllowedIPs alone cannot enforce TCP/UDP/ICMP port restrictions. Its local SQLite store holds peer names, WireGuard public keys, groups, allocated IPv4 addresses and directional rules. Registration produces a pending peer; a trusted administrator can approve it, then irreversibly revoke it. Revoked identities remain tombstoned. Legacy peer records migrate to pending. Only approved records are eligible for management access decisions and DNS previews. A local SQLite event history records these transitions without tamper-proof guarantees. A policy evaluator answers whether two recorded peers match an allowed protocol/port. A DNS endpoint previews A records. No packets traverse the process; no TUN device, WireGuard peer configuration, firewall, DNS socket, NAT helper, identity provider or relay exists.

## Security boundary

The API binds loopback, requires a runtime administrator bearer token, validates inputs and limits body sizes. It does not authenticate the holder of a public key as a specific enrolled machine, and it has no per-user authorization. **Access decisions are hypothetical until a separately built and tested enforcement agent applies them to actual traffic.** Do not configure production endpoints or assume packet isolation from these database policies.

## Local SQLite storage preflight

Management state stays local to a private directory owned by the service's effective Unix user. The immediate database directory must be owner-only (no group/other permissions); the SQLite database must be a single-linked, regular, process-owned file with no group/other permissions. Existing files are opened without following a final symlink and checked before SQLite initialization. New files are created with exclusive owner-only permissions.

**Upgrade behavior:** This preflight intentionally refuses preexisting permissive files or directories instead of silently changing their ownership or mode. The owner must first verify the correct backup and database path, preserve the existing state, and intentionally repair permissions using a trusted local administrator. Never delete or replace a failed-opening database automatically. A safe file preflight does not independently attest database contents or defend against a compromised same-user process; it does not provide signed policy, encrypted storage, or a deployed WireGuard data plane.

## GoreeCloud ecosystem roles

GoreeCloud VPN owns private networking, tunnel lifecycle, routing and network access enforcement. [GoreeCloud Mesh](https://github.com/GoreeCloud/mesh) owns cross-product integration/orchestration. [GoreeCloud UI](https://github.com/GoreeCloud/gc-ui) owns design tokens and user-interface acceptance. Avoid duplicating those systems.

## Deployment restrictions

No production deployment, live network modification or NetBird/Tailscale migration is covered by this code. Design and validate fail-closed device enrollment, revocation, audit, TLS/mTLS, HA and rollback before granting any real network privileges.

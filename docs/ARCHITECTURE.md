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

The Python API is a single-process *management-only* service. Its local SQLite store holds peer names, WireGuard public keys, groups, allocated IPv4 addresses and directional rules. A policy evaluator answers whether two recorded peers match an allowed protocol/port. A DNS endpoint previews A records. No packets traverse the process; no TUN device, WireGuard peer configuration, firewall, DNS socket, NAT helper, identity provider or relay exists.

## Security boundary

The API binds loopback, requires a runtime administrator bearer token, validates inputs and limits body sizes. It does not authenticate the holder of a public key as a specific enrolled machine, and it has no per-user authorization. **Access decisions are hypothetical until a separately built and tested enforcement agent applies them to actual traffic.** Do not configure production endpoints or assume packet isolation from these database policies.

## GoreeCloud ecosystem roles

GoreeCloud VPN owns private networking, tunnel lifecycle, routing and network access enforcement. [GoreeCloud Mesh](https://github.com/GoreeCloud/mesh) owns cross-product integration/orchestration. [GoreeCloud UI](https://github.com/GoreeCloud/gc-ui) owns design tokens and user-interface acceptance. Avoid duplicating those systems.

## Deployment restrictions

No production deployment, live network modification or NetBird/Tailscale migration is covered by this code. Design and validate fail-closed device enrollment, revocation, audit, TLS/mTLS, HA and rollback before granting any real network privileges.

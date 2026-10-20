# GoreeCloud VPN — Planned Features and Capabilities

> **Classification:** Proposed product capability catalog — not an implementation report.  
> **Product:** GoreeCloud VPN · **Repository:** `GoreeCloud/VPN` · **Category:** Secure networking, privacy, zero-trust access and VPN infrastructure.  
> **Recorded:** 2026-10-12 · **Lifecycle:** Fork-to-Native foundation / requirements backlog.  
> **Source:** Owner-provided “GoreeCloud VPN — Features & Capabilities” specification (2026-10-12).

## How to interpret this catalog

Every item below is a **proposed target capability**, not evidence of a delivered, operating, validated or generally available feature. An inherited NetBird implementation may provide a starting point, but must not be described as verified GoreeCloud functionality without exact-revision implementation and runtime evidence. Each item remains **Proposed / implementation unverified** unless later promoted through review, tests and verified lifecycle tracking in [Implemented Features](IMPLEMENTED-FEATURES.md) or the [Fork-to-Native roadmap](fork-to-native/ROADMAP.md). No item in this catalog alone authorizes a production deployment or security/privacy claim.

The source specification is arranged into 15 capability domains; the grouped entries below retain the intended subcapabilities while avoiding independent, conflicting records. Proposed sequencing is described in [Specifications](SPECIFICATIONS.md) and [Fork-to-Native roadmap](fork-to-native/ROADMAP.md).

## 1. Core VPN and networking

### Encrypted connectivity
- WireGuard-based and high-performance encrypted VPN tunnels; optional OpenVPN interoperability.
- End-to-end encrypted peer-to-peer communications; client-to-server, server-to-server and site-to-site connections; device-to-device private connections and remote network access.
- Full-tunnel, split-tunnel and application-specific routing.
- Persistent tunnels, always-on operation, automatic reconnection, connection failover and background VPN operation.
- IPv4, IPv6 and dual-stack support; secure use of public Wi-Fi.

### Peer-to-peer mesh networking
- Automatic peer discovery, full mesh, partial mesh and hub-and-spoke topologies.
- Direct, dynamic peer-to-peer tunnels with peer identity verification and secure authentication.
- Automatic peer configuration, private mesh addressing, stable device IP addresses and hostname-based discovery.
- Peer connectivity monitoring, cross-network and geographically distributed device communication, automatic inter-node routing and headless/unattended connections.

### NAT traversal and relay infrastructure
- Automatic NAT traversal, UDP hole punching, direct connection establishment and firewall traversal.
- NAT-type detection and symmetric NAT handling.
- Encrypted relay fallback via self-hosted or cloud-hosted relays; HTTPS/TLS-compatible and QUIC relaying.
- Automatic relay selection, redundancy, health monitoring, direct-to-relay fallback and connection recovery.

## 2. Advanced traffic obfuscation and stealth networking

### VPN transport obfuscation
- WireGuard traffic obfuscation and lightweight packet obfuscation.
- WireGuard over QUIC, TCP-compatible transports, UDP-over-TCP encapsulation and WireGuard over Shadowsocks.
- Shadowsocks-based obfuscation, obfsproxy, obfs4, V2Ray VMess over TCP or QUIC.
- TLS encapsulation, HTTPS-compatible transport, WebSocket transport, custom transport plugins and a modular pluggable-transport architecture.

### Fingerprint and traffic-analysis resistance
- Protocol fingerprint reduction, packet-size obfuscation, randomized padding and variable segmentation.
- Packet timing variation, inter-arrival timing modification, traffic shaping and traffic-pattern randomization.
- Traffic-flow analysis resistance, encrypted metadata minimization, cover traffic and traffic-correlation resistance techniques.
- Statistical fingerprint reduction, activity-pattern reduction, selected machine-learning analysis resistance, integration with multihop, configurable protection levels and privacy/performance trade-offs.

### Adaptive connectivity under network restrictions
- Restrictive-network and VPN-blocking detection; alternate transport selection and automatic protocol fallback.
- Port switching, custom ports, TCP/443 and QUIC/443 fallback.
- Obfuscated relays, censorship-resistant profiles and per-network obfuscation settings.
- Manual/automatic stealth mode, transport-level recovery, adaptive reconnection, restrictive-network diagnostics and performance-aware obfuscation selection.

**Assurance boundary:** Obfuscation is designed to reduce identification and traffic fingerprinting. It cannot guarantee undetectability, anonymity or protection against every correlation attack.

## 3. Zero-trust network access

### Identity and authentication
- Zero-trust design, default-deny access and identity-based authentication.
- SSO, OpenID Connect, SAML, MFA and external identity-provider integration.
- Users, groups, machines and service-account authentication; validated device identities.
- Certificate- and session-based authentication, reauthentication, temporary/expiring sessions, automated provisioning and SCIM synchronization.

### Policy and authorization
- RBAC, ABAC, identity-aware policies, least privilege and resource-level authorization.
- User-, device-, group- and application-specific resource permissions; TCP/UDP port, subnet and domain restrictions.
- Network segmentation, microsegmentation and environment isolation.
- Conditional access, just-in-time requests, temporary grants, expiration, approval workflows and immediate revocation.
- Policy-as-code support.

### Device trust and posture
- Registration, device approval, trusted-device validation and device ownership tracking.
- OS version/update checks, disk encryption, host firewall and endpoint-protection checks.
- MDM and EDR integration, device compliance policies, network-location checks and continuous device-health validation.
- Continuous reevaluation and automatic restriction of noncompliant devices.

## 4. Privacy and anonymous internet-access objectives

### Privacy-conscious account and data design
- Pseudonymous account identities and privacy-preserving registration without unnecessary mandatory personal information where appropriate.
- Privacy-preserving payment options if a paid service is introduced.
- Minimal metadata, data minimization, configurable retention, transparent privacy policies and privacy-focused infrastructure.

### Private internet traffic
- Encrypted browsing connectivity, public-IP masking through VPN exits and shared exit IPs.
- Geographic exit selection, protected internet egress and privacy-oriented exit infrastructure.
- DNS/IPv6 leak protection, reconnect behavior, local-network access controls, application exclusions and trusted/untrusted network profiles.

### Fail-closed networking
- System-wide kill switch, persistent firewall enforcement, always-on rules and lockdown mode.
- Blocking traffic on unexpected VPN disconnect and preventing accidental unencrypted connectivity.
- Firewall activation, local-network exceptions, IPv4/IPv6 filtering, app-level exceptions, secure reconnect and network-transition leak prevention.

### Privacy assurance
- Open-source client components, independently audited security components and reproducible builds where feasible.
- Protected cryptographic keys, key rotation, privacy-minimized telemetry and logging, transparent security architecture.
- Clear separation between identity-attributed enterprise access and privacy-oriented shared internet egress.

**Assurance boundary:** A VPN is not equivalent to total anonymity. Logging, exit-server trust, DNS handling, device compromise and adversary correlation must be evaluated against an explicit threat model before making privacy claims.

## 5. Advanced routing, internet exits and multihop

### Private-network routing
- Subnet, site-to-site, private LAN, cloud, VPC and cross-network routing.
- Route advertisement, centralized management, automatic distribution, NAT and masquerading.
- Overlapping subnet handling; domain, FQDN, wildcard, resource-based split tunneling and policy-based routing.
- Redundant private-network gateways.

### Internet exit nodes
- Self-hosted, managed and cloud-hosted exits with geographic selection.
- Automatic, latency-aware exit recommendations; administrator-enforced and user-selected exits.
- Egress policy enforcement, exit monitoring, failover, per-device exits and independent private/public traffic-routing policies.

### Multihop VPN
- Two-hop and multiple-hop routing; selectable entry/exit servers.
- Geographic/jurisdiction diversity, automatic recommendations and manual configurations.
- Adaptive routing, compatible obfuscation and traffic-analysis resistance, with performance-aware selection.

## 6. DNS and internet threat protection

### Private DNS
- Encrypted and private-network resolution, automatic device hostnames and internal DNS zones.
- Custom domains, split DNS, conditional forwarding and custom upstream resolvers.
- DNS-over-HTTPS and DNS-over-TLS, secure configuration distribution and VPN-protected DNS queries.
- Domain-based resource discovery, DNS leak prevention and internal hostname management.

### DNS filtering and threat blocking
- Advertisement, tracker, malware and phishing-domain blocking; malicious-destination filtering.
- Custom blocklists and allowlists, third-party filtering lists and category filters.
- Per-user, per-device and network-wide filtering; privacy-oriented DNS profiles and advanced tracker protection.
- DNS security events and administrator-managed DNS policies.

**Integration dependency:** Coordinate with GoreeCloud DNS where the relevant platform contracts support integration; do not assert that the integration exists.

## 7. Secure remote access and private resource connectivity

### Resources
- Secure SSH and SFTP; RDP and VNC; internal websites, APIs and applications.
- Database, NAS, file-server, private-cloud, Kubernetes and IoT connectivity.
- Remote infrastructure administration and access without publicly exposing protected resources.

### Browser access
- Browser-based SSH, RDP and terminal sessions; clientless access where supported.
- Authenticated and policy-controlled sessions, time limits, expiration and session audit support.

### Service publishing
- Private and explicitly configured public application publishing; reverse proxies.
- HTTP/HTTPS and TCP/UDP proxying, TLS passthrough and certificate automation.
- Custom domains, application access gateways, expiring sharing links, identity-protected URLs.
- Optional password/PIN controls, SSO protection and resource-specific policies.

### Privileged access
- Identity-aware SSH, short-lived certificates and certificate-based privileged sessions.
- Just-in-time permissions, administrative session controls, session recording/auditing, elevation expiration and centralized management.

## 8. File transfer and device sharing

- Encrypted device-to-device sharing, authorized private transfer and transfer without publicly opened inbound ports.
- Cross-platform and temporary file transfer; direct peer paths when possible and encrypted relay-assisted paths otherwise.
- Device discovery, sharing permissions, progress display, failure recovery and private-network sharing.

## 9. Enterprise network administration

### Centralized management
- Unified administration of VPN networks, organizations, users, groups and device inventories.
- Device approvals/revocations, peers, resources, gateways, relays, connectors and DNS.
- Identity providers, roles, permissions, security policies, network access, access requests and configuration deployment.

### Monitoring and audit
- Authentication, enrollment, device removal, admin, resource-access and policy-change events.
- Connection diagnostics, peer direct-versus-relayed state, relay/connector/route health and DNS security events.
- Device posture, administrative activity, SSH session auditing, exportable audit records, SIEM integration and alerts.
- Advanced anomaly detection as a separate later-stage capability.

### Performance operations
- Latency, loss, throughput, tunnel and gateway health; relay performance and availability.
- Network diagnostics, connection failure analysis, transport-obfuscation overhead, multihop performance and automated troubleshooting.

## 10. Deployment, infrastructure and automation

### Deployment options
- Self-hosted, managed and hybrid infrastructure; on-premises, cloud, VPC, multi-cloud, branch-office, home-lab and edge deployments.
- Private gateways, self-hosted coordination, relays and exits; self-hosted identity and policy adapters.

### Provisioning and operations
- Docker and containerized deployments, Kubernetes and operators, Terraform, IaC, configuration-as-code and policy-as-code.
- GitOps, REST APIs and CLI automation; machine/service-account provisioning.
- Automatic enrollment, ephemeral enrollment credentials, configuration rollout and credential rotation.
- High availability, health checks, redundant coordination and relays, disaster recovery, backup and restoration.

## 11. Cross-platform applications

### Target environments
- Windows, macOS, Linux, Android, iOS, iPadOS, ChromeOS.
- Headless Linux, containers, network appliances, routers, NAS and embedded Linux.
- Actual support depends on native VPN APIs, device privileges, system restrictions and feasible maintenance.

### Native client experiences
- Native desktop/mobile apps, graphical connection management and a CLI.
- Tray/menu-bar integration, background services and automatic startup.
- One-click connect, profiles, exit selection, health indicators, private device/resource directories.
- DNS, split tunneling, obfuscation, kill switch and multihop settings; diagnostics and notifications.
- Trusted Wi-Fi detection, auto-connect on untrusted networks, multiple organization profiles and accessibility.

## 12. Cryptography and security architecture

- WireGuard cryptographic foundations, modern authenticated encryption and secure key agreement.
- Unique device cryptographic identities, secure generation and protected private-key storage.
- Key rotation, ephemeral session keys where supported and forward secrecy.
- Certificate-based infrastructure authentication, appropriate certificate pinning and mutual TLS.
- Advanced research targets: quantum-resistant and hybrid classical/post-quantum key establishment, subject to reviewed standards and cryptographic agility.
- Secure device enrollment/authorization, signed identity records, revocation and independently auditable/testable security components.

## 13. Adaptive connectivity and operational automation

### Connectivity recovery
- Network-change detection and recovery during Wi-Fi/cellular transitions.
- Persistence where feasible, automatic reconnect, transport and direct-to-relay fallback.
- Gateway failover, exit health monitoring, automatic DNS reconfiguration and adaptive path selection.
- Latency/bandwidth-aware optimization, obfuscation-aware transport decisions and secure fallback/diagnostics.

### Enforced policies
- Startup and always-on requirements, trusted-network policies and compliance-controlled access.
- Identity-based connection rules, expiring permissions/sessions, revocation and device offboarding.
- Connection-profile automation, API-driven changes and centrally enforced security policy.

## 14. GoreeCloud ecosystem integration objectives

| Proposed integration | Responsibility | Current claim |
| --- | --- | --- |
| GoreeCloud Mesh | Peer discovery, private overlay networking and routing | Proposed; independent implementation evidence required |
| GoreeCloud Identity | Account authentication, device identity and SSO | Proposed; independent implementation evidence required |
| GoreeCloud Policy | Authorization, zero trust, conditional access and configuration enforcement | Proposed; independent implementation evidence required |
| GoreeCloud Observability | Diagnostics, health, audit events and privacy-minimized security telemetry | Proposed; independent implementation evidence required |
| Wardveil Security | Threat protection, posture and access safeguards | Proposed; independent implementation evidence required |
| Privacy Shield | Leak protection, privacy controls and metadata minimization | Proposed; independent implementation evidence required |
| GoreeCloud Manager | Centralized management, configuration and operational control | Proposed; independent implementation evidence required |

Also evaluate the existing [Fork-to-Native integration assessment](fork-to-native/INTEGRATIONS.md), which tracks Everkeep and GoreeCloud UI as separate applicable/evaluation integrations. Future GoreeCloud DNS integration is governed by verified platform contracts, not this catalog.

## 15. Proposed unified operating modes

| Mode | Proposed functions |
| --- | --- |
| Private Internet | Encrypted egress, privacy-oriented exits, DNS protection and kill switch |
| Mesh Network | Protected device-to-device connectivity and private networks |
| Zero-Trust Access | Identity-based access to authorized private resources |
| Stealth VPN | Pluggable obfuscated transport and restrictive-network connectivity |
| Maximum Privacy | Multihop, privacy safeguards and selected traffic-analysis resistance |
| Remote Access | SSH, RDP, internal services and protected applications |
| Site-to-Site | Encrypted branch/cloud infrastructure routing |
| Enterprise Security | Device posture, identity policy, admin controls and auditing |
| Custom | User-specified routing, DNS, gateways and security controls |

## Backlog lifecycle and dependencies

- **All catalog entries:** Proposed, not implemented as verified GoreeCloud VPN capabilities.
- **Near-term architectural prerequisites:** audited upstream inventory, threat model, licensing, source/build evidence, identity and policy boundaries, no unauthorized upstream traffic.
- **Foundational delivery dependencies:** WireGuard/private mesh, enrollment, ACL and revocation, DNS/routing, security/kill-switch enforcement, platform permissions and recovery.
- **Advanced research / later phases:** stealth transports, cover traffic, multihop, post-quantum key establishment, anomaly detection and privacy assurance. No claimed security outcome without threat-model-specific verification.
- **Business-facing and administration dependencies:** reliable management plane, organization policy, audit boundaries, self-hosted operations, browser remote access, publishing and privileged operations.
- **Release gate:** secure, reproducible builds; cryptographic and network-leak tests; policy and revocation tests; real device/network and OS coverage; privacy, licensing, accessibility, migration and rollback evidence. See [Fork-to-Native security constraints](fork-to-native/SECURITY.md).

A capability moves from this catalog to implemented tracking only after a reviewer identifies its source implementation, test coverage, exact commit, supported environments, observed runtime behavior, open limitations and release status. Implemented source code alone is **not** proof of a production-certified feature.

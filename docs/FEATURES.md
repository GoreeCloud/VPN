# GoreeCloud VPN — features, functions and capabilities

**Product specification:** founder-directed target scope, November 3, 2026. **This document is a roadmap of intended functionality, not a statement of shipped capabilities.** Read [ROADMAP](ROADMAP.md) and source/tests for actual maturity.

GoreeCloud VPN is a privacy-first, self-hosted Zero Trust connectivity platform for individuals, families, developers, organizations and enterprises. It is intended to connect people, devices, applications, private infrastructure, cloud workloads and services with owner-controlled identity, encryption, routing and policy.

## 1. Core VPN and encrypted mesh networking
- WireGuard tunnels, end-to-end encryption, private device identities and peer-to-peer mesh connectivity.
- Full/partial meshes, device/user/service/network connectivity, automatic discovery, private address allocation and key distribution.
- IPv4, IPv6, dual-stack, STUN/ICE and UDP NAT traversal, firewall/CGNAT handling, direct traffic and encrypted relay fallback.
- Persistent/on-demand/always-on operation, background service, cellular/Wi-Fi roaming, split/full tunneling, auto-reconnect and connection profiles.

## 2. Advanced network routing
- Site-to-site, device-to-site, subnet, VPC, cloud/on-premises, LAN, remote office and multicloud networking.
- Internet exit nodes, regional egress, selectable gateways, redundant routes, gateway monitoring and failover.
- Static/dynamic route advertisement and approval, policy, destination, domain, application and group-based routing.
- IPv4/IPv6, NAT, source preservation, overlapping subnet handling, segmentation, firewalls and router integration.

## 3. Zero Trust security and access
- Default-deny policy, ACL, RBAC and ABAC; user/group/device/service/application/resource authorization.
- Source/destination, TCP/UDP/ICMP and port restrictions, directional policies and microsegmentation.
- Temporary, just-in-time, privileged access, device authorization, cryptographic admission, policy tests/versioning.
- Automated policy distribution, credential revocation, quarantine, lateral-movement restriction and audit trails.

## 4. Authentication and identity
- SSO, OIDC, OAuth, SAML, MFA, passkeys, security keys and passwordless authentication.
- Self-hosted identity, LDAP/AD, Entra ID, Google Workspace, Okta, Keycloak and SCIM provisioning.
- Invitations, accounts/teams/organizations, group sync, contractors and guests, lifecycle and cross-organization boundaries.
- Machine identities, service accounts, API tokens, expiring and one-use enrollment, session control and key rotation.

## 5. Device posture and endpoint security
- Device approval, identities, OS/client version checks, managed-device and security compliance.
- EDR/MDM integrations, including Intune, CrowdStrike, SentinelOne, process and custom posture attributes.
- Network/region restrictions, automatic reevaluation, expiration, quarantine, event logs and posture dashboards.

## 6. GoreeCloud Private DNS
- Private device names, FQDNs, internal DNS zones, A/AAAA/CNAME, aliases and service discovery.
- Split DNS, conditional forwarding, resolver priorities, suffixes, search domains and group-level settings.
- DNS forwarding over authorized routes, Active Directory, Pi-hole, AdGuard Home and Unbound integration.
- DNS APIs, monitoring, private routing and failover.

## 7. Secure remote administration
- Identity-aware and passwordless SSH, browser terminals and browser RDP.
- Windows/Linux/macOS, hypervisor, NAS, router, database and Kubernetes administrative access.
- Per-user policies, account restrictions, SSH approvals, privileged session management and optional recording.
- Session audits, expiry, revocation, multiple sessions and supported clipboard functionality.

## 8. Reverse proxy and secure publishing
- Private/public application publishing, HTTPS and managed TLS, custom domains, service URLs and webhooks.
- HTTP/S, TCP, UDP, TLS passthrough, SNI, path routing, WebSocket and Server-Sent Events.
- SSO, password, PIN, tokens and identity-aware authorization; IP, geographic and reputation filters.
- Header/redirect forwarding, multiple backends, temporary previews, expiry, health and access logging.

## 9. Private services
- Named services, stable addresses, private registry/DNS and independent service identities.
- Registration, multi-host availability, redundancy, host health, discovery, migration and failover.
- User/group/service-to-service authorization, private applications/APIs/databases and regional administration.

## 10. Secure file sharing
- Encrypted peer-to-peer send/receive, drag and drop, progress, notifications, large files and recovery.
- User-approved destinations, permissions, history and cross-platform transfer.
- Read-only/read-write shared folders, WebDAV, SMB/CIFS, NFS, SFTP, NAS, media and backup access.

## 11. Devices and fleet management
- Central inventory, registration, groups/tags, naming, ownership, private IP/DNS, activity and online status.
- Approval, expiration, revocation, key lifecycle, posture and configuration profiles.
- Headless/ephemeral devices, zero-touch provisioning, MDM, unattended operation, updates and APIs.
- Multiple organizations, private networks and profile switching.

## 12. Cross-platform applications
- Linux, Windows and macOS desktop clients; Linux/Windows Server and ARM/Raspberry Pi.
- Android, iOS and iPadOS with mobile roaming, background/always-on VPN and notifications.
- FreeBSD where supported, Docker/Podman, Kubernetes, virtual machines, NAS, routers, edge/IoT and VPS.
- Compatible TV platforms, browser-based administration and browser remote access where platform APIs permit.

## 13. Monitoring and diagnostics
- Network topology, connection/relay state, latency, bandwidth, tunnel, gateway and route metrics.
- DNS, NAT, firewall and connection diagnostics; flow, source/destination, protocol and denial visibility.
- Auth and administrative audit logs, activity search, export/retention and alerts.
- Prometheus, Grafana, SIEM, email, webhooks and incident reports.

## 14. Self-hosting and infrastructure ownership
- Self-hosted control, coordination, signaling, relays, identity and databases, with optional managed hosting.
- Docker/Compose, Kubernetes, VPS/bare metal, custom domain, environment-based configuration and secure APIs.
- Backup/restore, migration, infrastructure-as-code, health, horizontally scaled/HA systems and regional redundancy.
- Controlled upgrades and rollbacks, private data residency, owner-managed logging and dependency transparency.

## 15. APIs, automation and developer tools
- REST APIs for users, devices, groups, policies, routes, DNS, applications and services.
- Scoped tokens, OAuth clients, Terraform, GitOps, GitHub/GitLab CI and ephemeral job identities.
- Kubernetes operators/CRDs, ingress/egress, Gateway API and multi-cluster/pod networking.
- Userspace/embedded networking, SDKs, local forwarding, webhooks and compliance diagnostics.

## 16. Performance, availability and reliability
- Optimized direct paths, low-latency tunnels, relays, geographic selection and keepalive/roaming.
- Gateway redundancy, service failover, route health, rolling upgrade and control-plane HA.
- Resource/battery efficiency, network quality statistics, recovery plans and operational monitoring.

## 17. Privacy, encryption and security
- WireGuard cryptographic identities, end-to-end tunnel encryption and client-held private keys.
- Encrypted relay traffic, key rotation/revocation, signed enrollment and optional preshared keys.
- Experimental post-quantum exchange only after separate review; encrypted management and secret storage.
- Least-privilege defaults, isolated administration, minimal telemetry and configurable log retention.

## 18. AI and intelligent networking
- AI agent/workload/service/data connectivity and private self-hosted language model access.
- Identity-aware AI gateways, provider key custody, model allowlists, request routing, rate and budget controls.
- Token/spend attribution, audit, MCP tool permissions, agent boundaries and optional data inspection/filtering.

## 19. Enterprise and organizational capabilities
- Tenants, teams, administrators, SSO/directories, managed devices and department isolation.
- Guests/contractors, cross-organization trust, MSP administration and delegated management.
- Compliance evidence, SIEM, PAM, approvals, automated provisioning, HA and tenant-aware billing.

## 20. Personal, family and home networking
- Home LAN, server, NAS, printer, camera, automation, backup and media access.
- Travel VPN/exit nodes, secure public Wi-Fi, household identities and child/guest policies.
- Device invitation, mobile access, reconnection and private monitoring.

## 21. Specialized connectivity
- Developer/CI/private Git and databases, external technical support and remote administration.
- IoT, industrial, edge and surveillance networking; compatible gaming/LAN and media services.
- Regional egress, external VPN providers, staging/test and serverless/container infrastructure access.

## 22. GoreeCloud VPN interface
- Authoritative GoreeCloud UI branding, typography, components, color tokens and accessibility.
- Native responsive desktop/mobile, light/dark, high contrast, screen readers and reduced motion.
- Connection controls, topology, peers, routing, DNS, policies, remote access, transfers and publishing.
- Dashboards, analytics, onboarding, alerts, troubleshooting, recovery and administrator settings.

## 23. Intelligent diagnostics and recovery
- Continuous connection evaluation, direct/relay selection, network roaming, route and gateway health.
- DNS/configuration failures, expired credentials, link diagnostics and secure automated recovery.
- Incident reporting, alerts, guided remedies, rollback and availability reporting.

## 24. Administration and governance
- Unified configuration/permission administration, policy templates, versioning and audit.
- Export/import, backups, secret management, access reviews and compliance checks.
- Staged configuration, testing, rollback, upgrade readiness, capacity and operational reporting.

## Architectural components

Control plane; client; mesh engine; routing; relay; identity; security; Private DNS; gateway; SSH/RDP; secure transfer; monitor; automation; AI gateway; GC UI management console.

## Verification rule

No planned capability is labeled implemented until code, integration tests, security review and platform-specific verification support that claim. The current code is a limited management-plane foundation and does not change or depend on existing NetBird/Tailscale deployments.

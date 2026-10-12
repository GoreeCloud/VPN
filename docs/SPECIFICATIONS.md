# GoreeCloud VPN — Product Specifications

> **Status:** Proposed product definition, derived from the owner-supplied capability catalog dated 2026-10-12. The repository remains a **NetBird-derived Fork-to-Native engineering foundation**, not a tested, released or independently certified GoreeCloud VPN.

## Product definition

**GoreeCloud VPN** is intended to be a privacy-first secure-networking platform combining encrypted VPN tunnels, peer-to-peer mesh networking, zero-trust resource access, private-internet egress, optional obfuscated transports, multihop routing, DNS and threat protections, secure remote access, centralized administration, automation, observability and cross-platform native clients.

Target audiences include individuals, home labs, organizations, developers, distributed services and cloud/branch infrastructure. Differing user models must be kept distinct: consumer internet privacy, attributable enterprise access and managed infrastructure cannot share ambiguous trust or audit defaults.

The complete owner-proposed, **not-yet-verified** requirements catalog belongs in [Planned Features](PLANNED-FEATURES.md). This file establishes conceptual boundaries, implementation priorities and acceptance constraints rather than duplicating the catalog.

## Architecture principles

1. **Privacy by design:** Collect the minimum appropriate metadata; provide truthful logging and retention disclosures.
2. **Zero trust by default:** Authenticate and explicitly authorize users, devices, networks and resources; maintain default-deny behavior.
3. **Encrypted transport and safe keys:** Rely on reviewed cryptographic protocols; protect private key material and support secure rotation and revocation.
4. **Infrastructure independence:** Design self-hosted, managed and hybrid options without locking basic safe operation to an unverified hosted service.
5. **Censorship resistance where viable:** Modular alternative transports should degrade safely, be measurable and not promise invisibility.
6. **Native cross-platform experience:** Use real platform APIs, appropriate privileged agents, Glaze standards and accessible controls, accounting for OS restrictions.
7. **Least privilege and clear boundaries:** Separate private resource access, public egress, management-plane authority and client privileges.
8. **Performance and recovery:** Prefer direct tunnels, use encrypted relays when needed and recover safely across network changes.
9. **Extensibility and auditability:** Modular transport, identity, policy and network components; documented APIs and integration contracts.
10. **Transparent state:** Clearly expose effective mode, route, DNS, gateway, exit, security protections, connection health and limitations.
11. **Verified GoreeCloud integration:** Integration names denote targets only until contract conformance and runtime evidence establish availability.

## Core system responsibilities (proposed)

| Boundary | Responsibility | Key security consideration |
| --- | --- | --- |
| Native clients and privileged agents | Device enrollment, tunnel control, routing, firewall/DNS changes and trustworthy UI | OS permissions, fail-closed recovery, clear consent, signed upgrades |
| Coordination/management plane | Device inventory, identities, authorization, network policy, private addresses and topology | Explicit trust, least privilege, secure admin access, revocation |
| Peer and relay data path | Direct encrypted tunnels, NAT traversal, authorized relay fallback | Never treat relay transit as access authorization; verify E2E confidentiality |
| Exit and subnet gateways | Internet egress and private routing | IPv4/IPv6 and DNS leak defenses, scoped route permissions, failure safety |
| Identity and Policy adapters | SSO/device identity, compliance and per-resource access decisions | Contract ownership, durable revocation and defense in depth |
| DNS/security adapters | Private DNS resolution and optional threat filtering | Secure fallback and no unexpected resolver leakage |
| Audit/observability | Diagnostic, policy and security events | Minimized sensitive data, retention and role-controlled access |
| Mode/transport extensions | Obfuscation, multihop, file transfer and remote access | Independent threat models, no unsupported anonymity claims |

## Simplified operating modes (proposed)

The owner-specified modes are **Private Internet, Mesh Network, Zero-Trust Access, Stealth VPN, Maximum Privacy, Remote Access, Site-to-Site, Enterprise Security and Custom**. Each is a preset of permitted network/security behavior—not proof that a mode has been built. Their detailed feature scope is defined in [Planned Features](PLANNED-FEATURES.md#15-proposed-unified-operating-modes).

Modes should expose exact route and exit scope, DNS behavior, tunnel and kill-switch state, identity implications and expected performance trade-offs. Transitions must not temporarily route traffic outside the selected protection boundary.

## Key product decisions and open dependencies

- **Fork-to-Native:** Preserve upstream source/licensing provenance and maintenance safety while replacing product-defining behavior only through reviewed, compatible increments. See [Upstream provenance](fork-to-native/UPSTREAM.md).
- **Trust models:** Maintain separate privacy-oriented internet egress and enterprise access policy/logging models. “Anonymous” must not imply absolute anonymity.
- **Stealth:** Pluggable transports are advanced objectives; evaluate compatibility, adversary model, legal restrictions, performance and fallback without claiming undetectability.
- **DNS ownership:** Coordinate with GoreeCloud DNS only after platform contracts and verified functionality exist.
- **Security platform integration:** Identity, Mesh, Policy, Observability, Manager, Privacy Shield, Wardveil, Glaze and other proposed integrations remain unverified; use the [Integration assessment](fork-to-native/INTEGRATIONS.md).
- **Platform support:** Windows, macOS, Linux, Android, iOS/iPadOS, ChromeOS, headless and network appliances are targets, not supported release claims.
- **Credentials and secrets:** Do not check active credentials, private keys, device identifiers or production endpoints into public source or documentation.
- **Release and licensing:** Verify BSD-3-Clause / AGPL-3.0 obligations, source provenance, security controls, privacy claims and operational behavior before any release or hosted service.

## Delivery sequence and acceptance

1. **M0 — Source foundation:** Audited upstream snapshot, licensing, guarded automation and scoped build/test evidence. Partly achieved.
2. **M1 — Security and functional inventory:** Map actual inherited behavior and endpoints; test policy, key, routing/DNS, firewall, IPv4/IPv6 and device enrollment behavior. Incomplete.
3. **M2 — Native trust contracts:** Establish GoreeCloud identity, policy, cryptographic boundary, management and integration evidence. Planned.
4. **M3 — Native application experience:** Native platform clients, Glaze design, accessible onboarding, trustworthy permission UX and signing. Planned.
5. **M4 — Independent architecture:** Progressive migration from inherited product-defining workflows, with compatibility and rollback. Planned.
6. **M5 — Release acceptance:** Reproducible builds, full tests, real-network and leak verification, security/privacy/licensing review, fail-closed recovery, signed packages and guarded release approval. Planned.

The authoritative milestone and partial test results remain in the existing [Fork-to-Native roadmap](fork-to-native/ROADMAP.md) and [Security baseline](fork-to-native/SECURITY.md); this specification does not supersede those technical status records.

## Current implementation statement

As of the 2026-10-12 repository inspection, current verified reporting supports a source-import foundation, narrowly scoped Go tests/ACL fixes and headless signal/relay source compilation only. It does not support claims of a released VPN, independent GoreeCloud clients, advanced traffic obfuscation, anonymous egress, enterprise management, completed platform integrations or deployment readiness. See [Implemented Features](IMPLEMENTED-FEATURES.md) and [README](../README.md).

## Completion and evidence rule

Promote individual features only when source ownership, exact revision, relevant build/test matrix, supported platform, runtime verification, privacy/security behavior, limitations, migration and rollback evidence, and product-release status are distinguishable. A documented plan or a passing isolated unit test is not equivalent to production readiness.

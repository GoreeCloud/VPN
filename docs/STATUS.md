# GoreeCloud VPN implementation status

Status: early development (November 3, 2026). The public repository originally contained only a placeholder README. This file documents the delivery boundary: no production deployment, no claim of working WireGuard tunnels, and no modification of the existing NetBird installation.

Development checkpoint: peer records require explicit administrator approval, revocation preserves a permanent key tombstone, pre-approval databases migrate to pending, and local lifecycle events are recorded. These are management-state controls only; no actual data-plane security is asserted.

See docs/THREAT_MODEL.md for specific identity, packet-policy, route, relay and release requirements. A read-only peer planning preview has been added, but does not configure WireGuard or enforce traffic.

Priority sequence: secure identity and enrollment; real WireGuard data-plane enforcement; routing and DNS; clients; observability; remote access; enterprise and AI modules. GoreeCloud Mesh owns inter-product orchestration, while GoreeCloud UI governs visual surfaces.

# GoreeCloud VPN security boundaries

This source represents a **first-party control-plane preview**, not an operational VPN.

**Identity:** All peer registry APIs require one high-entropy bearer administrator token saved in an owner-only 0600 file. Only the /healthz and optionally enabled static UI assets are unauthenticated. There are no per-user roles, MFA, SSO or token rotation API. Use it on loopback, not the public Internet. Remote listeners require TLS and separate network/firewall access controls.

**Network:** A peer record is a registration record, not an allowed WireGuard session or firewall permission. Never conflate the registry's 10.77.0.0/24 development allocation with a production routed subnet. No routing, peer ACL, DNS, relay or kill switch is implemented. Do not automatically open gateways or assign public DNS based on this registry.

**Privacy:** The server stores device names, public keys and reserved addresses in a local owner-private directory; no analytics or telemetry are emitted. Browser/Android credentials remain in memory. Sensitive data must be excluded from logs and public source. Android backups and cleartext traffic are disabled.

**Data safety:** The state path must be a real 0700 directory with a private state file. Atomic replace and fsync protect changes from partial writes, but separate processes writing the same directory are not supported; run one daemon per state directory. Back up the private state outside public Git. No restore rehearsal has been completed.

**Threats remaining:** CSRF is not meaningful with explicitly supplied bearer headers and no credential cookies, but XSS, token theft from process memory, DoS/rate limits, certificate provisioning, log redaction, policy bypass, unsafe remote control, race conditions at runtime, peer revocation propagation, VPN DNS leaks and host firewall changes need independent review. A loopback-only preview must not be exposed through a publicly accessible reverse proxy without a production authentication and authorization design.

Security responsibilities: Wardveil handles cybersecurity and threat defense; GoreeShield governs consent/data minimization; GoreeCloud Identity must eventually enforce role-aware permissions. Mesh cannot expand authority by discovering an API.

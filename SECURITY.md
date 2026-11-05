# GoreeCloud VPN security policy

**Pre-production alpha.** Do not use this software to protect real traffic: the current policy evaluator does not enforce data-plane access, no tunnels are established, and no client authentication is implemented.

## Safeguards in the current foundation

- The management HTTP API is restricted to loopback addresses.
- An administrator token of at least 32 characters is required at runtime.
- No secrets, private WireGuard keys, or deployed configuration values are checked into Git.
- Public WireGuard peer keys are validated and then require a short-lived X25519/HKDF/HMAC key-possession proof before administrative approval; this alone is not remote identity authentication or hardware attestation.
- Prior alpha-approved peers are deliberately demoted to pending during this migration and must be freshly verified. A peer must be approved within five minutes of proof.
- Proof challenges expire after two minutes, allow one attempt, are memory-bounded, and are invalidated by management restarts. Only expected HMAC values—not ephemeral private keys—are retained in the in-memory cache.
- Real WireGuard connection revocation and packet enforcement are **not yet implemented**.
- All newly registered peers enter `pending` state. Only admin-approved records are eligible for positive management policy decisions or preview DNS names.
- `revoked` is terminal and the key tombstone remains for duplicate-key rejection. Existing pre-approval databases migrate peers to `pending` (fail closed).
- Local lifecycle events are informational SQLite entries, **not** immutable enterprise audit evidence.
- Approved-peer WireGuard adjacency is currently **read-only intent**; exported peer stanzas are not full configurations or enforced network access.
- VPN address pools and exported host prefixes must be within RFC1918 private IPv4 ranges.
- SQLite state is local and owner-restricted on POSIX systems.
- Default-deny means policy *decisions* deny unless a matching allow rule exists, not that actual packets are blocked.
- Management JSON writes reject duplicate object member names (including nested members) and nonstandard NaN/Infinity values before any state mutation, in addition to existing field and size validation. Browser cross-origin access is not enabled.

## Required security gates before production

Authenticated device enrollment and key possession, TLS/mTLS, identity-aware authorization, real WireGuard tunnel integration, actual firewall or equivalent data-plane enforcement, device revocation, hardened DNS and routing, audit trails, security reviews, integration/adversarial tests, controlled rollout, backup and recovery.

Report vulnerabilities privately to the authorized GoreeCloud maintainers rather than posting secrets or exploit details in public issues. Licensing and final release security policy are not yet finalized.

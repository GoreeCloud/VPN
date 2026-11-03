# GoreeCloud VPN security policy

**Pre-production alpha.** Do not use this software to protect real traffic: the current policy evaluator does not enforce data-plane access, no tunnels are established, and no client authentication is implemented.

## Safeguards in the current foundation

- The management HTTP API is restricted to loopback addresses.
- An administrator token of at least 32 characters is required at runtime.
- No secrets, private WireGuard keys, or deployed configuration values are checked into Git.
- Public WireGuard peer keys are validated but are not proof of device possession.
- All newly registered peers enter `pending` state. Only admin-approved records are eligible for positive management policy decisions or preview DNS names.
- `revoked` is terminal and the key tombstone remains for duplicate-key rejection. Existing pre-approval databases migrate peers to `pending` (fail closed).
- Local lifecycle events are informational SQLite entries, **not** immutable enterprise audit evidence.
- SQLite state is local and owner-restricted on POSIX systems.
- Default-deny means policy *decisions* deny unless a matching allow rule exists, not that actual packets are blocked.
- Requests are authenticated, size limited, and validated. Browser cross-origin access is not enabled.

## Required security gates before production

Authenticated device enrollment and key possession, TLS/mTLS, identity-aware authorization, real WireGuard tunnel integration, actual firewall or equivalent data-plane enforcement, device revocation, hardened DNS and routing, audit trails, security reviews, integration/adversarial tests, controlled rollout, backup and recovery.

Report vulnerabilities privately to the authorized GoreeCloud maintainers rather than posting secrets or exploit details in public issues. Licensing and final release security policy are not yet finalized.

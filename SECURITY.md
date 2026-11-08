# GoreeCloud VPN security policy

**Pre-production alpha.** Do not use this software to protect real traffic: the current policy evaluator does not enforce data-plane access, no tunnels are established, and no client authentication is implemented.

## Safeguards in the current foundation

- The management HTTP API is restricted to loopback addresses.
- Every HTTP request must use the exact bound loopback IP literal and port as its single Host header. Unexpected and duplicate Hosts are rejected to reduce DNS-rebinding and virtual-host confusion.
- Browser Origin headers and absolute-URI request targets are rejected; this prototype does not serve a browser UI, issue cookies or enable CORS. This is a defense in depth, not remote authentication.
- An administrator token of at least 32 characters is required at runtime.
- No secrets, private WireGuard keys, or deployed configuration values are checked into Git.
- Public WireGuard peer keys are validated but are not proof of device possession.
- A nonapplying local SQLite **policy revision ledger** demonstrates serialized per-audience compare-and-swap high-water storage, including concurrency refusal and surviving normal reopen. It explicitly does **not** verify a signature, prevent file/backup restoration rollback, atomically bind a kernel update, or authorize packet policy; see [offline ledger](docs/OFFLINE_POLICY_REVISION_LEDGER.md).
- **Draft PR #6 remains unmerged pending independent cryptographic review (issue #7):** its local proof protocol reuses the static WireGuard X25519 private key in a separate HKDF-SHA256/HMAC-SHA256 challenge. The Noise protocol's static-key reuse warnings (https://noiseprotocol.org/noise.html) require careful cross-protocol analysis; no exploit has been demonstrated and no production approval is implied.
- An optional **offline** approved-peer key/IP manifest validates canonical public keys, unique RFC1918 /32 mappings and endpoints; it explicitly does not verify current kernel AllowedIPs, device key possession, signed policy or live enforcement.
- All newly registered peers enter `pending` state. Only admin-approved records are eligible for positive management policy decisions or preview DNS names.
- `revoked` is terminal and the key tombstone remains for duplicate-key rejection. Existing pre-approval databases migrate peers to `pending` (fail closed).
- Local lifecycle events are informational SQLite entries, **not** immutable enterprise audit evidence.
- Approved-peer WireGuard adjacency is currently **read-only intent**; exported peer stanzas are not full configurations or enforced network access.
- CI workflow third-party GitHub Actions are pinned to **full, verified upstream commit SHA references** rather than mutable major-version tags, with negative regression checks preventing future unpinned additions or broad repository-token permissions. Pins limit unexpected tag moves but still require regular upstream security review; this does **not** provide signed build provenance.
- Wheel verification now checks **every archive member against RECORD SHA-256/SHA-384/SHA-512 digest and byte length**, rejects missing/extra entries, duplicate/unsafe paths, symlinks, private data extensions and license/metadata omissions; regression tests deliberately tamper with wheel files to confirm fail-closed behavior. RECORD consistency is **not signed provenance** and cannot detect an adversary rebuilding an entire wheel with new hashes.
- A **test-only** rootless namespace helper now verifies public peer readback against one approved policy snapshot and applies a fixed compiled nftables batch only to its disposable lab chain; unexpected kernel peer or unexpected nftables rule means reject without changing nft state. Its exact JSON readback checks one fixed lab chain shape, **not** authenticated production ownership or protection against validation-to-apply races. A controlled rootless fault-injection test now verifies a fallback to **compiler-generated default deny** after simulated post-apply readback failure; this is not durable crash-safe production recovery and a failed fallback still requires external intervention. This is not a trusted production agent or an authenticated policy source.
- An experimental one-snapshot ingress preflight composes approved key-to-/32 intent, directional group/port policy and **untrusted public** WireGuard AllowedIPs text. A mismatched peer causes a `ValidationError`, not a deployable bundle; successful text matching still has no device or kernel attestation.
- An experimental, offline nftables IPv4 INPUT preview now expresses group policies as stateless ingress matches and an **interface-wide final drop** for otherwise-unmatched WG INPUT traffic. The isolated lab verifies another reachable local IP cannot bypass this rule after target-specific allow. It can also render a **nonapplied** `nft -f` replacement batch for a pre-existing dedicated preview chain. Only the manually invoked disposable lab tests the kernel batch and rejection behavior. No trusted GoreeCloud agent, production firewall owner, established-connection revocation, routing or authenticated peer key-to-IP binding exists.
- VPN address pools and exported host prefixes must be within RFC1918 private IPv4 ranges.
- SQLite state is local and owner-restricted on POSIX systems.
- Default-deny means policy *decisions* deny unless a matching allow rule exists, not that actual packets are blocked.
- Requests are authenticated, size limited, and validated. Browser cross-origin access is not enabled.

## Required security gates before production

Authenticated device enrollment and key possession, TLS/mTLS, identity-aware authorization, real WireGuard tunnel integration, actual firewall or equivalent data-plane enforcement, device revocation, hardened DNS and routing, audit trails, security reviews, integration/adversarial tests, controlled rollout, backup and recovery.

Report vulnerabilities privately to the authorized GoreeCloud maintainers rather than posting secrets or exploit details in public issues. Original GoreeCloud repository code is MIT licensed; the independent production security review remains incomplete.

# GoreeCloud VPN — offline SQLite policy revision ledger

**Status: experimental, nonapplying local precondition. NOT authenticated replay defense, not an agent, not production approval.**

`goreecloud_vpn.policy_revision_ledger.OfflinePolicyRevisionLedger` is an explicitly local, opt-in SQLite store for a *revision high-water mark*. It is independent of the experimental, **unmerged** [Ed25519 signed-policy verification draft PR #34](https://github.com/GoreeCloud/VPN/pull/34) and the original **unmerged** static WireGuard X25519 key-possession draft PR #6. It never imports or requires a cryptographic library.

## What the local ledger checks

- Caller supplies an **absolute dedicated `.sqlite3` path** whose parent already exists and is an owner-only directory. The DB must be a private regular file owned by the current user with a single hard link; path symlinks, public/shared parent permissions and world-readable existing files fail closed. Newly created database files use mode `0600`.
- The SQLite connection uses **`synchronous=FULL`** and the standard rollback journal (`journal_mode=DELETE`), with a bounded lock wait.
- `read(audience="goreecloud-agent:node-id")` retrieves the current stored revision, defaulting to zero for an uninitialized device audience.
- `compare_and_advance(key_id="controller-key-1", audience="goreecloud-agent:node-id", expected_previous=..., next_sequence=..., payload_sha256=...)` requires a well-formed key identifier, exact audience, strictly increasing signed 63-bit integer sequence and lowercase 64-character digest. The **single serialized `BEGIN IMMEDIATE` transaction** compares the current committed revision to the caller's expected prior value. On a mismatch, rollback/error; on success, commit the new revision.
- The high-water mark is keyed by **device audience rather than controller signing-key ID**. Key rotation cannot silently reset or fork the per-device sequence counter. Independent audiences have separate counters.
- Unit tests cover reopen persistence, concurrent writers, stale/duplicate/lower sequence refusal, controller signing-key change, malformed input, unsafe database paths and failure rollback. One test *explicitly demonstrates* a rollback attack by restoring old database bytes.

## Stored-record corruption refusal — November 10, 2026

A ledger read and a compare-and-swap transition now both reject malformed **existing** key IDs, lowercase SHA-256 digests and stored revision integers, rather than trusting the sequence integer alone. The revision remains per audience; failure raises a fixed `ValidationError` before any revision is advanced. This is an integrity-*format* check, not cryptographic authentication, corruption repair or source provenance. Independently modified **well-formed** records and complete SQLite file restores can still pass local syntax checks, so a trusted external monotonic anchor and atomic firewall state transition remain P0 release gates. Tests intentionally tamper with a disposable SQLite fixture and confirm no new sequence is committed.

## Integration is deliberately blocked

A future agent may need to read a trusted revision floor, verify a controller signature with a trusted clock and signing key, parse and validate the *entire* proposed policy, then reconcile kernel state and update the revision atomically. **This module does not combine any of those steps.** It will happily store a caller-provided digest without proving it was signed. There is no allowed IPC, network endpoint, permission escalation, privileged nftables execution or WireGuard access. A successful SQLite write **must not** be interpreted as permission to accept traffic.

### Known limitations and remaining release gates

1. **Restoring old SQLite files, filesystem snapshots or VM backups resets the high-water mark.** SQLite's durable transaction is not a hardware-sealed monotonic counter. Host-root or a process with write access can replace the file. Anti-rollback under hostile root, stolen disk, clock rollback, data-loss recovery and device reprovisioning require a separately authenticated, tamper-resistant design and independent review.
2. SQLite cannot atomically commit a **kernel firewall change** in the same DB transaction. Advancing the counter *before* kernel application may consume a policy revision on failure; advancing it *after* kernel application leaves a replay window after crashes. Neither ordering is approved for production.
3. No trust anchor, signed policy issuer, key rotation trust ceremony, TPM/secure hardware attestation, trusted clock, device enrollment or independent cryptographic verification is established here. Unrecognized key identifiers do not become trusted.
4. A successful revision CAS only proves **one local SQLite connection's** ordering, not authenticated network/device state or resilience to a malicious privileged concurrent actor. Fail closed if any precondition, signature or post-apply verification cannot be established.
5. The management alpha still does **not** provide a functional VPN. Full least-privileged agent, INPUT/OUTPUT/FORWARD/IPv6/conntrack controls, kernel peer AllowedIPs, secure key management, outage recovery and independent review remain P0 in [issue #22](https://github.com/GoreeCloud/VPN/issues/22).

Do not combine this with draft [PR #34](https://github.com/GoreeCloud/VPN/pull/34) in a production path without an independently reviewed atomic state-transition protocol. GoreeShield privacy and Wardveil security constraints remain in force; GoreeCloud Mesh cannot bypass them.

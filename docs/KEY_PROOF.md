# WireGuard key-possession verification — local prototype

**Security status:** independently testable local management protocol, not a production enrollment service, mutual authentication system, device attestation solution, or data-plane enforcement.

## Goal

A public WireGuard key is not, by itself, proof that the registering machine holds its corresponding private key. GoreeCloud VPN now requires a short-lived cryptographic demonstration of private-key possession before the management store can mark a peer approved.

## Protocol: goreecloud.vpn.key-possession.v1

1. A trusted administrator registers a device's **public** WireGuard key. The peer remains `pending`.
2. The administrator requests `POST /api/v1/peers/{id}/challenge` from the loopback-only management API. It returns a 120-second, single-use challenge containing an opaque challenge ID, random 32-byte nonce, ephemeral server X25519 public key, target peer ID, and registered peer public key.
3. Via an appropriately trusted out-of-band channel, the administrator transfers the challenge object to the device. **Never transfer the administrator bearer token or the device private key.**
4. On the **device only**, an X25519 implementation uses the existing WireGuard private key and the ephemeral server public key to derive a shared secret. HKDF-SHA256 (salt = challenge nonce; context = `goreecloud-vpn/peer-key-possession/v1`) derives a proof key. HMAC-SHA256 authenticates a canonical JSON transcript binding protocol version, peer ID, challenge ID, nonce, server public key and registered peer public key.
5. The administrator submits the resulting base64 proof to `POST /api/v1/peers/{id}/prove` using the same challenge ID. The server performs a constant-time comparison against its expected value and consumes the challenge even when the attempt fails.
6. Only a successful proof sets `proof_verified_at`. The administrator must explicitly approve within **five minutes** of that proof using `POST /api/v1/peers/{id}/approve`. Approval does not start a tunnel or grant operating-system permissions.

## API shape

`POST /api/v1/peers/{id}/challenge` — no body; administrator bearer token required.

Returns `{"challenge": {"protocol": "...", "peer_id": "...", "challenge_id": "...", "nonce": "...", "server_public_key": "...", "peer_public_key": "...", "expires_in_seconds": 120}}`.

`POST /api/v1/peers/{id}/prove` — body `{"challenge_id": "...", "proof": "<base64 32-byte HMAC>"}`; administrator bearer token required.

The Python helper `goreecloud_vpn.enrollment.device_proof(device_private_key, challenge)` is intended to run **only on the device holding the key**. It accepts an in-memory X25519PrivateKey object and returns the proof string. It does not transmit or write the device private key. For test fixtures, do not reuse hard-coded keys in actual deployments.

## Defensive design

- Ephemeral server private keys are not persisted; each challenge stores only the expected HMAC, device identity, and monotonic expiration in memory.
- A challenge is single-use; issuing another challenge for the same peer invalidates its predecessor. Expired challenges are discarded, and the cache is limited to 256 active challenges per management process.
- Restarting the management process invalidates unconsumed challenges.
- Revoked identities cannot be reapproved or successfully prove after revocation; the existing public key remains a tombstone.
- Unknown, expired, modified, misbound and replayed proofs cannot mark devices verified.
- The device-side v1 challenge parser rejects unknown fields, oversized or nonprinting/non-ASCII transcript fields, and malformed expiration metadata **before** doing X25519 exchange. This is input-resource/ambiguity hardening only.
- The `expires_in_seconds` response field is advisory and is **not** included in the v1 authenticated transcript; the server enforces expiration with its own monotonic clock. Never rely on that client-visible number to determine authorization, and do not silently extend this protocol without a new version and independent review.
- A database upgrade automatically resets previously approved **pre-proof** peer records to pending. An administrator must repeat proof and approval. This is intentionally disruptive and fail-closed.
- The original key-possession protocol can verify that a holder knows the static X25519 private key. It does **not** establish OS integrity, hardware origin, user identity, remote service authenticity, or production-grade key custody.

## Remaining prerequisites

Before production use: mutually authenticated encrypted enrollment transport; delegated one-time invitations rather than distributing a global administrator token; device-specific identities and recovery; authenticated agent-to-management communication; rate limits and durable audit; threat-model review by a cryptography specialist; real WireGuard interface configuration; and packet-level enforcement/teardown on revocation. See [THREAT_MODEL](THREAT_MODEL.md) and [ROADMAP](ROADMAP.md).

No live GoreeCloud VPN, NetBird, VPS or firewall state is changed by this work.


## November 9, 2026 — current-main integration review (still draft)

An isolated merge-based reconciliation of this draft with current GoreeCloud VPN main brought in the merged policy-intent, kernel readback, HTTP framing and request-resource test suites. The initial combined Python test run failed **36 tests and raised 10 errors** because the inherited fixtures attempted approval using a registered public key alone; those calls must not bypass the proposed key-possession requirement.

The changed **test-only** fixtures now generate deterministic disposable X25519 private/public pairs and exercise the real `ProofChallenges.issue → device_proof → ProofChallenges.verify → administrator approve` sequence before accepting a peer. The fixture helpers and seeded keys live strictly in `tests/` and are not part of the installed application wheel. An HTTP framing regression now verifies a correctly framed approval request still returns 404 **until** the genuine proof succeeds, then 200 after it succeeds. Additional negative fixtures reject unowned private keys and revoked peers. Existing production code never derives device secrets from a public key; the test seed mapping is intentionally artificial and must never be reused for real clients.

The current branch remains **DRAFT / nondeployable**. Test and wheel integrity do not replace independent scrutiny of static WireGuard X25519 key reuse in a separate protocol, its transcript/channel binding, KDF and HMAC inputs, approval race semantics, migration of previously approved records, key revocation, audit/logging, authenticated remote enrollment, packet enforcement, or host compromise/backup rollback. Do not merge or deploy without those explicit gates.

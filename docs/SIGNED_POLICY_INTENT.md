# GoreeCloud VPN — experimental signed policy intent (OFFLINE ONLY)

**Security status: prototype, independent review required, no deployable authority.** This optional module verifies a time-bounded, recipient-scoped *detached policy-byte digest* signed with a **separate Ed25519 controller key**. It does **not** sign messages, provision trusted keys, open a network socket, enroll devices, attest the kernel, invoke a policy agent, modify WireGuard/nftables, or store durable replay protection. It must not be wired to privileged networking until P0 #22 and independent security review #7 are complete.

## Separation from WireGuard and GoreeCloud Identity

- The controller's Ed25519 signing key pair must be **independently generated** and held by a reviewed authority. **Never reuse a WireGuard static X25519 private/public key** as this policy-signing identity. Keep controller private key material off endpoints and out of GitHub, logs, databases and examples.
- A future GoreeCloud Identity enrollment flow must securely provision or pin **only the approved controller Ed25519 public key(s)** to the intended device. A key identifier inside a received envelope **does not grant trust**. Verification takes a separate, already-trusted `trusted_public_keys` map; unrecognized/removed keys fail closed.
- A signature binds specific policy **bytes** to one `goreecloud-agent:<node>` audience, a monotonically increasing sequence, issuance/expiry times and a domain-separated canonical message. The actual policy payload must **still be independently validated** for schema, ownership, source-to-key bindings and fail-closed packet rules by a separately reviewed verifier.
- Management-plane consent and data minimization are governed by GoreeShield. Wardveil reviews the cryptographic and kernel security boundaries. Mesh may coordinate approved policy distribution but cannot weaken signature or privacy checks.

## Wire format

UTF-8 JSON with **exactly eight fields**, rejecting duplicates and unknown fields:

| Field | Required value |
| --- | --- |
| `schema` | `goreecloud.vpn.signed-policy-intent.ed25519.v1` |
| `key_id` | Pinned controller signing-key identifier (1–64 ASCII letters/digits/`_`/`-`) |
| `audience` | Exact intended `goreecloud-agent:<node>` identifier |
| `sequence` | Positive signed 63-bit revision, strictly greater than **externally maintained** last accepted revision |
| `issued_at` | Integer Unix seconds; must not be over 30 seconds ahead of the trusted clock |
| `expires_at` | Integer Unix seconds, strictly later than issue time and current trusted time, with **maximum 600-second validity** |
| `policy_sha256` | Lowercase SHA-256 hex digest of **exact policy bytes**, size 1 to 1,048,576 bytes |
| `signature` | Canonical standard Base64 of the **64-byte Ed25519 signature** |

The signature is checked over the ASCII bytes:

```text
"GoreeCloud VPN policy intent verification v1\x00"
+ JSON({all fields except signature}, sort_keys=True, separators=(",",":"), ensure_ascii=True)
```

JSON duplicates, nonfinite values, noncanonical digest/signature, unexpected fields, unknown keys, modified payload bytes, wrong audience, replayed/lower revisions, expired or overlong grants and invalid signatures are rejected. Envelopes exceed 4,096 bytes are rejected. Only the standard audited `cryptography` Ed25519 primitive is used, never a custom signature implementation. See the upstream API: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

The verifier takes **trusted inputs** `now`, `minimum_sequence`, `expected_audience` and `trusted_public_keys` supplied independently by a future hardened agent. It returns a verification result with `signature_verified=true` but deliberately sets **`replay_state_persisted=false`, `enrollment_authenticated=false`, `kernel_state_attested=false`, `agent_invoked=false`, `applied=false`, `data_plane_enforced=false`**.

## Development use

Install the optional reviewed dependency, **not required by the management alpha**:

```shell
python -m pip install -e '.[policy-signatures]'
python -m unittest discover -s tests -q
```

The optional extra is bounded to `cryptography>=50.0.2,<51` (PyPI project current stable observed November 7, 2026); the local development laptop's system `cryptography` may be older. Dependency license (Apache-2.0 OR BSD-3-Clause) and version range require standard release supply-chain, vulnerability and license review before use. The package does **not** contain a production signing key, command sender or network-facing verifier service. Unit tests generate disposable Ed25519 keys **only in memory**.

## Test-only combination with the offline revision ledger

The updated **draft** tests in `tests/test_signed_policy_ledger_integration.py` exercise **two separate experimental primitives together without shipping a service**: read the local per-device sequence floor, verify detached Ed25519 claims against an independently trusted public key and that floor, and only then attempt the local SQLite `compare_and_advance` transaction. Tests cover a genuine signed policy, wrong signer/recipient/payload, equal/older signed revision, controller signing-key rotation, two valid **racing** signed revisions (one wins, the stale competing writer fails), and a simulated *old database restore* that **reverts the recorded floor**. See [OFFLINE_POLICY_REVISION_LEDGER](OFFLINE_POLICY_REVISION_LEDGER.md).

This is deliberately a **unit-test demonstration, not an exported verified-and-apply API**. Advancing the ledger does **not** change a firewall or prove a valid enrollment; it only records a candidate revision locally. There is no chosen production order for ledger advance versus kernel apply, since either ordering has a crash window. **Do not use this demonstration as a privileged agent transaction.** A restored disk/VM backup still defeats the local anti-replay floor; only an independently reviewed trusted monotonic anchor and transaction protocol can address that.

## Unresolved production security gates

1. Independent cryptographer/protocol reviewer must assess message format, exact canonicalization, signature and digest binding, algorithm/authority domain separation, key lifecycle, clock assumptions and failure cases. This is **not** a replacement for independent review of draft [PR #6](https://github.com/GoreeCloud/VPN/pull/6).
2. Ship trusted public keys by an authenticated enrollment / secure provisioning mechanism; define key rotation and revocation, no delegation or trust based on untrusted `key_id` text.
3. Persist `minimum_sequence` as a crash-safe, anti-rollback high-water mark. Verification **alone does not update it**. A trusted monotonic clock or securely bounded time source and expiry handling are required to withstand clock rollback.
4. Bind the signed payload to the exact locally expected device, interface, policy schema and current authorized peer public-key / `AllowedIPs` state, with complete atomic transaction/recovery behavior. No such agent is implemented.
5. Validate command-source authorization, rate limits, cross-namespace and packet-path ownership, reboot/offline behavior, multi-device scope and negative enforcement tests before production use.

**Do not feed the verifier result directly into privileged kernel commands.** Issue [#22](https://github.com/GoreeCloud/VPN/issues/22) is the governing release gate, and the standalone crypto enrollment draft remains unmerged.

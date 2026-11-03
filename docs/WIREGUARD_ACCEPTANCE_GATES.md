# Isolated WireGuard and Zero Trust acceptance gates

Status: **test design only** (2026-11-03). This document does not implement a tunnel, firewall, authentication protocol, or production security boundary. See [P0 issue](https://github.com/GoreeCloud/VPN/issues/1), [threat model](THREAT_MODEL.md), and [roadmap](ROADMAP.md).

## Safety boundary

Run only in disposable Linux network namespaces or isolated CI virtual machines, with synthetic keys and addresses and no route to production networks. Do not reuse NetBird identities, gateways, credentials, DNS, firewall state, or host routing. Do not run privileged integration tests on a production host. Namespace creation and teardown must be confined to a dedicated ephemeral runner; if isolation cannot be verified, skip the test and fail the release gate.

## Required independent evidence

| Gate | Positive proof | Negative/failure proof |
| --- | --- | --- |
| Cryptographic peer identity | Each endpoint generates its own WireGuard private key; authenticated enrollment binds an authorized identity to the matching public key; packet exchange succeeds between two isolated peers | Wrong-key or unapproved peer cannot establish authorized connectivity; no private key is sent to the controller |
| Real encrypted data plane | WireGuard handshake counters advance and application payload passes over the tunnel in both directions | No tunnel/handshake means no claimed VPN connectivity; packet capture on the underlay must not expose application plaintext |
| Default-deny enforcement | An explicitly authorized peer-to-peer protocol and destination port works | Unmatched peer, destination, TCP/UDP port, and ICMP traffic is blocked at the actual packet boundary, not merely rejected by the management API |
| Revocation | Authorized traffic works before revocation | Revoked peer loses real packet access within a documented maximum interval; stale agent state and control-plane outage cannot restore access |
| Failure isolation | Expected connectivity recovers after agent restart or control-plane restoration | Restart, dropped updates, expired credentials, and malformed policies never turn deny into allow |
| Routing and cleanup | Only intended test CIDRs are routed through the tunnel | Conflicting subnet and invalid route requests fail closed; after teardown no test interfaces, firewall rules, namespaces, or routes remain |
| Repeatability | Fresh-run CI artifacts identify kernel, WireGuard implementation, test image, commit, and pass/fail results | A skipped privileged test is reported as **not verified**, never as passed |

## Implementation order

1. Add a pure policy compiler with explicit, versioned input/output contracts and unit tests for default deny, directionality, protocol, port ranges, group membership, and malformed/unknown identities. Do not equate evaluator decisions with packet enforcement.
2. Select an audited WireGuard implementation; document licensing and endpoint private-key custody. Implement proof-of-possession enrollment without exposing private keys.
3. Build a disposable two-peer namespace harness with deterministic setup/cleanup and no default route to the host's real network. Require root privileges only inside the isolated runner.
4. Apply policy through a reviewed packet filter in the test namespace. Assert both allowed traffic and denied traffic with real sockets/packets, including peer revocation and disconnected-controller cases.
5. Publish reproducible CI logs and test evidence before checking off any P0 milestone. Require separate approval and a rollback plan before any deployment outside the isolated test environment.

## Release decision

A green Python unit-test suite or a rendered WireGuard configuration is insufficient. **Production-ready = false** until the real handshake, negative packet tests, revocation behavior, isolation, and failure-mode gates above have passed in supported environments. Keep the current management-only alpha warning in the README until then.

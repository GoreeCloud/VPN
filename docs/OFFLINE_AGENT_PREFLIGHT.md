# GoreeCloud VPN — single-snapshot offline ingress preflight

**Status:** experimental **read-only inspection**. This is not a VPN agent, authenticator, rule applier, or deployment permission. It cannot establish trustworthy kernel state or a production authorization decision.

## Scope

`goreecloud_vpn.agent_preflight.build_offline_ingress_preflight(store, target_peer_id, public_allowedips_text, interface="wg0")` composes three already-existing offline building blocks from **one** frozen `VPNStore.snapshot()`:

1. Approved peer public keys and unique RFC1918 IPv4 `/32` intent from [IDENTITY_BINDING_INTENT](IDENTITY_BINDING_INTENT.md).
2. Directional group/source/target/port nftables **INPUT-only preview** from [NFT_INGRESS_PREVIEW](NFT_INGRESS_PREVIEW.md).
3. A strict comparison of supplied public `wg show INTERFACE allowed-ips` text against the *exact* source peers authorized to send inbound traffic to this target, using [KERNEL_ALLOWEDIPS_READBACK](KERNEL_ALLOWEDIPS_READBACK.md).

If any inbound source is missing, has a wrong key or `/32`, or if an extra unrelated/revoked peer appears in the supplied text, the function **raises `ValidationError` and emits no bundle**. Even a source with a valid approved key is excluded unless a stored directional group policy permits an inbound flow to that target. Reversed policies do not grant ingress. A pending or revoked peer is not eligible.

The function reads management state once and copies it to an immutable-by-convention internal working snapshot before running the separately implemented compilers. This prevents accidental mixing of *two different database reads within that calculation*. It does **not** verify that the underlying database, authorization or kernel remains unchanged afterward. The output checksum is only a local change detector and is explicitly **not signed or authenticated**.

## Returned evidence and limitations

The structured response contains the selected peer IDs, approved public-key binding manifest, public-text comparison, offline nftables INPUT preview and a canonical SHA-256 fingerprint. All deployment and trust flags are false: `candidate_sha256_is_authenticated`, `kernel_readback_authenticated`, `agent_invoked`, `applied`, `data_plane_enforced`, and `production_ready`. Its `single_snapshot_compiled` field means **only one local management snapshot was used**, not that any data-plane state has been attested.

The candidate is **ingress-only and local-to-one-target**, intended for a dedicated two-endpoint lab interface. An interface that also needs outgoing-only WireGuard adjacency requires a different authorized peer-selection contract. A production agent must not install this manifest's selected subset indiscriminately. The current nftables INPUT-only preview adds a terminal drop for all unmatched traffic arriving on the named WireGuard interface; its chain policy remains `accept` for other interfaces. This does **not** establish a full data-plane default-deny or production-safe firewall. OUTPUT, FORWARD, IPv6, subnet routing, return flows, established conntrack, interleaved traffic and production crash recovery are not implemented.

## Validation in the disposable rootless lab

The manual `--run --policy-preview` test creates fresh rootless user, network and mount namespaces, uses only temporary private-tmpfs keys, and generates a local SQLite approval/policy fixture. It stores a **temporary** management snapshot on the same private tmpfs, then obtains the receiving kernel's **nonsecret public** `allowed-ips` text. The new preflight validates that the kernel source peer matches the approved incoming policy in that one snapshot, and that the generated nftables preview matches the separately produced test fixture. It does not read `wg show dump`, install a production service, or connect to the outside network.

A future agent needs authenticated enrollment, signed and versioned policy, protected kernel readback from the expected interface and network namespace, privilege separation, generation-pinned transaction preconditions and complete packet-path coverage. It must demonstrate fail-closed boot/crash/outage behavior, packet races, rollback, multi-peer scopes and independent security review before deployment. See P0 [issue #22](https://github.com/GoreeCloud/VPN/issues/22).

## Bounded offline compilation — November 10, 2026

The preflight now rejects non-list peer or policy snapshots, more than 4,096 peer records, more than 4,096 policy records, or more than **1,000,000 conservative peer × policy comparisons** before making additional deep copies and entering the preview compilers. This controls the upper bound on one specific nested policy evaluation; it does not bound the upstream SQLite snapshot query itself, its memory allocation, or malicious implementation of the caller-provided store.

Failure returns `ValidationError` without a candidate bundle and does not invoke network, nftables or WireGuard commands. Synthetic tests verify oversized peer inventories, oversized policies, combinations that exceed the evaluation budget, non-list snapshots and normal small valid snapshots. The limits govern **offline alpha acceptance only**, not an approved production fleet capacity. All existing trust, identity, rollback and kernel enforcement gates remain open.

## November 10, 2026 — preserve caller-owned SQL transactions

The bounded offline snapshot now first requires the shared SQLite connection to be idle. It refuses a nested request with a fixed `ValidationError` instead of accidentally rolling back the caller's existing transaction when SQLite rejects a second `BEGIN`. The snapshot's error handler also rolls back only a transaction that this specific snapshot successfully started. A disposable regression test stages a peer change in a caller-owned transaction, verifies both direct bounded reads and the preflight refuse the nested call, and proves the pending update remains until the caller performs its own rollback.

This check is not a substitute for a dedicated read-only SQLite connection, cross-process database protection, a signed policy transaction, crash-safe firewall application, or production acceptance.

## November 10, 2026 — bounded SQLite source snapshot

Production `VPNStore` now implements an explicit `snapshot_bounded(max_peers=..., max_policies=...)` read for this **offline, unapplied** preflight. Each fixed-order SQL query uses `LIMIT n+1`, refuses a count overflow **before decoding all rows into Python objects**, and reads peers and policies inside the same SQLite read transaction under the store lock. The preflight selects this bounded method when it exists; synthetic snapshot adapters retain their previous single-call read interface and still face post-read size checks.

This reduces peak allocations from peer/policy inventories and prevents a concurrent SQLite writer from silently mixing peer and policy generations inside this particular read transaction. The exact limits remain 4096 peers, 4096 policies, and at most 1,000,000 offline pair evaluations. It does **not** cap individual JSON/SQL row sizes, transaction lock waits outside SQLite's configured timeout, DB file size, disk IO, or malicious custom store implementations. It does **not** create a signed policy, kernel enforcement, service availability guarantee, or production VPN readiness.

Synthetic regression tests cover caps before decoding, transaction closure after refusal, ordinary small snapshots, and proof that the real VPNStore preflight path does not call its legacy unbounded `snapshot` method.

## November 10, 2026 — bounded SQLite row and aggregate byte budgets

The nonapplying source preflight now enforces **three separate resource dimensions** under the same SQLite read transaction: `LIMIT n+1` for at most 4,096 peers and 4,096 policies; the SQLite connection's `SQLITE_LIMIT_LENGTH` at at most **64 KiB per encoded row/value** before results are transferred to Python; and an **8 MiB combined snapshot byte budget**, checked incrementally in batches of at most 64 raw rows *before* decoding JSON or running any policy compiler.

The helper never raises an existing stricter SQLite connection limit. It temporarily lowers a more permissive limit under the store lock and restores the caller's exact prior value on success **or failure**. The existing caller-owned-transaction refusal and rollback-only-own-transaction rule are unchanged. Exhausted limits fail closed with fixed `ValidationError` classifications; no private peer or policy content enters the error message. Tests exercise an oversized SQLite text value, aggregate budget exhaustion, retained stricter caller limits, normal snapshots, and no resulting database mutation.

These caps cover **one trusted local SQLite snapshot used only for offline compilation**. They do not bound on-disk database size, SQLite sort/index work, SQLite extension code, other endpoints, Python allocator overhead, or the size of malicious data outside this read path. They do not sign a policy, authenticate kernel state, configure WireGuard, enforce firewall policy, approve a production fleet size, or confer production VPN readiness.

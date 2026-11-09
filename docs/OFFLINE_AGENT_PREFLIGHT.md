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

The candidate is **ingress-only and local-to-one-target**, intended for a dedicated two-endpoint lab interface. An interface that also needs outgoing-only WireGuard adjacency requires a different authorized peer-selection contract. A production agent must not install this manifest's selected subset indiscriminately. The existing nftables preview only drops unmatched traffic destined to the specific local target IP; it is **not an interface-wide default-deny**, and the chain policy is `accept`. OUTPUT, FORWARD, IPv6, subnet routing, return flows, established conntrack, interleaved traffic and production crash recovery are not implemented.

## Validation in the disposable rootless lab

The manual `--run --policy-preview` test creates fresh rootless user, network and mount namespaces, uses only temporary private-tmpfs keys, and generates a local SQLite approval/policy fixture. It stores a **temporary** management snapshot on the same private tmpfs, then obtains the receiving kernel's **nonsecret public** `allowed-ips` text. The new preflight validates that the kernel source peer matches the approved incoming policy in that one snapshot, and that the generated nftables preview matches the separately produced test fixture. It does not read `wg show dump`, install a production service, or connect to the outside network.

A future agent needs authenticated enrollment, signed and versioned policy, protected kernel readback from the expected interface and network namespace, privilege separation, generation-pinned transaction preconditions and complete packet-path coverage. It must demonstrate fail-closed boot/crash/outage behavior, packet races, rollback, multi-peer scopes and independent security review before deployment. See P0 [issue #22](https://github.com/GoreeCloud/VPN/issues/22).

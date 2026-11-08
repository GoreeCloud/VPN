# GoreeCloud VPN — offline peer key/address binding intent

**Status:** experimental, read-only, nonapplying design artifact. It is **not a device enrollment proof**, authenticated packet-policy distribution, kernel WireGuard peer configuration, firewall control or VPN service.

## What it produces

Call `goreecloud_vpn.identity_binding.build_key_address_binding_intent(store)` on a local `VPNStore`. The function examines a consistent management-state snapshot and returns one deterministic entry for each **approved** peer with:

- The management peer ID and canonical-format WireGuard **public** key.
- Exactly one assigned, usable RFC1918 IPv4 `/32` `AllowedIPs` *intent*, validated against the configured VPN address pool.
- An optional validated `host:port` endpoint.

Pending and revoked records are excluded. The compiler **fails closed** if an approved entry has an invalid public key, address, endpoint or lifecycle status, or if approved keys, addresses or peer IDs collide. It never contains a private key, administrator bearer token, group membership or other unnecessary account details.

The output provides `schema: goreecloud.vpn.key-address-binding-intent.v1`, `binding_count`, and `snapshot_sha256`. The SHA-256 fingerprint is **only a deterministic change detector, not a signature or authority proof**: the output explicitly says `snapshot_sha256_is_authenticated: false`, `key_possession_verified: false`, `active_wireguard_state_verified: false`, `applied: false`, and `data_plane_enforced: false`.

This manifest intentionally includes approved peer records even when the current group policy has no matching allowed flow. It describes candidate peer identity/address inventory, **not** which peers should be connected, which communications are allowed, or what production WireGuard peers currently exist. A future agent must derive an independently authorized set of active peers.

## Hard release boundaries

**WireGuard cryptokey routing** uses peer `AllowedIPs` as a route/received-source permission mapping. Validating local stored public-key strings is not verifying that a device controls its private key or that the kernel has installed this mapping. A source address can never be treated as an independently authenticated identity. The experimental [public AllowedIPs readback parser](KERNEL_ALLOWEDIPS_READBACK.md) can compare selected approved mapping intent with text collected from an isolated kernel test, but it does not authenticate that text or read private keys. A future trusted, least-privileged agent must first authenticate device enrollment; reconcile the actual installed public key and `AllowedIPs` per interface; check no overlaps or unexpected peers exist; and **only then** compile and atomically apply packet policy.

The rootless lab now includes an independent receiver-side `AllowedIPs` /`32` check and attempted source spoof, but these results do **not** prove that GoreeCloud VPN performed admission or policy enforcement. The lab also tests reverse-direction default deny; its stateless INPUT-only rules do not implement safe bidirectional connection state or return traffic.

See [the P0 agent acceptance issue](https://github.com/GoreeCloud/VPN/issues/22), [the offline nftables preview](NFT_INGRESS_PREVIEW.md), and [the isolated kernel lab](ISOLATED_WIREGUARD_LAB.md). Do **not** feed this module output directly into privileged networking tools or a production agent.

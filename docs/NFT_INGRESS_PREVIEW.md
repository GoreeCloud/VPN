# GoreeCloud VPN — read-only nftables ingress policy preview

**Status:** early experimental policy compiler. It generates **offline** Linux nftables text from local, administrator-approved peer and group records. It never executes `nft`, configures WireGuard, changes routes, accesses privileged sockets, or installs firewall rules.

## Purpose and current contract

`goreecloud_vpn.firewall_preview.build_nft_ingress_preview(store, target_peer_id, interface="wg0")` reads a single consistent snapshot of SQLite-managed peer and policy state. It accepts only approved peers and explicit directional `source group → target group` policies. A source peer must be different from the target, approved, belong to the policy source group, and have an IPv4 address in the configured RFC1918 VPN pool.

Its deterministic nftables text contains:

- Validated Linux interface names (at most 15 restricted ASCII characters; no shell interpolation).
- Explicit IPv4 source / destination combinations and `tcp`, `udp` destination-port or `icmp` allow matches.
- A **terminal drop** for other incoming IPv4 packets addressed to the target peer through that WireGuard interface.
- A fixed preview table name and no private keys, subprocess calls, or sensitive administrative token.

The returned JSON-shaped plan explicitly reports `applied: false` and `data_plane_enforced: false`. Generating valid text does not establish an active security boundary.

## Demonstrated disposable Linux test

The opt-in rootless laboratory accepts a separate `--policy-preview` mode:

```sh
WG_BIN=/absolute/path/to/verified/wg bash tests/integration/wireguard_rootless_smoke.sh --run --policy-preview
```

The script first creates isolated user, network and mount namespaces. It generates two disposable WireGuard key pairs on private tmpfs. A test fixture registers the **matching public keys** in a fresh local management SQLite database, creates approved peer records in groups `users` and `services`, and generates:

1. An ingress preview with no allow policies. After applying it **inside the receiving lab namespace only**, the encrypted ICMP test fails as expected.
2. A preview with an explicit `users → services, icmp` policy. After replacing the lab-only table, encrypted ICMP succeeds.
3. A separate policy preview containing only allowed TCP destination port **8443** and UDP destination port **5353**. A temporary TCP/UDP echo listener is bound to the receiving peer's private overlay IP only. Through the actual WireGuard tunnel, ports 8443 and 5353 are reachable and the otherwise-listening TCP port 8444 and UDP port 5354 are dropped as unauthorized.
4. A WireGuard peer-key removal on the receiver. Traffic fails again, even while the manually allowed TCP/UDP rules are present.

The script uses `nft -c` before any experimental application. Private keys and temporary database files are kept on a bounded private tmpfs and automatically cleaned during normal exit. Network interfaces and firewall rules disappear when the disposable namespaces end. It never uses `sudo` and never modifies host, NetBird, VPS or production networking.

**Verified November 7, 2026:** Generated default-deny blocked traffic; generated ICMP allow passed; allowed TCP/UDP port probes succeeded; denied TCP/UDP port probes failed; peer removal stopped traffic. The isolated test returned zero and private key directory count was zero. The socket probe has its own strict rootless namespace guard and refuses host-network execution.

## Critical limitations and production blockers

- **Not deployed.** The management daemon does not request, authenticate or apply these rules. The test script applies them manually in a rootless network namespace.
- **INPUT only.** There is no OUTPUT, FORWARD, IPv6, subnet routing, exit-node or established-connection policy. The basic TCP/UDP port probes show destination-port filtering on a new connection/datagram, **not** fully stateful TCP return traffic, midstream revocation, conntrack safety or directional flow tracking.
- **No atomic update.** The test replaces its own table by deleting and re-adding it between scenarios. This is **not** a fail-closed production-safe rollout, and must not be reused on hosts.
- **No cryptographic peer authorization by itself.** IP addresses and group membership in the preview are not trustworthy unless a privileged agent verifies the real WireGuard peer public key and `AllowedIPs` binding.
- **No live revocation orchestration.** The test manually removes a peer key. Product revocation must also address existing connections, conntrack state, rule distribution failure and control-plane loss.
- **No third-party or host firewall integration.** A real agent needs least-privilege boundaries, ownership of its dedicated rule tables, no interference with NetBird, validated transactions, rollback and independent security review.

See [the threat model](THREAT_MODEL.md), [the manual lab description](ISOLATED_WIREGUARD_LAB.md), and [the roadmap](ROADMAP.md). Do not use this preview as a production firewall configuration.

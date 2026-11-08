# GoreeCloud VPN — disposable WireGuard kernel lab smoke

**Status:** verified on the authorized Linux development laptop on November 7, 2026. This is a manually invoked **kernel primitive acceptance test**, not the GoreeCloud VPN network agent, automatic policy enforcement or a deployed VPN.

## Safety and scope

The script `tests/integration/wireguard_rootless_smoke.sh` requires the explicit `--run` argument. Before any network mutation, it creates new **rootless user, network and mount namespaces** using `unshare -Urnm`, and verifies its process is not in the parent's original network or mount namespace. It refuses to run as host root.

Inside its disposable network namespaces it creates two veth-linked peers, generates temporary WireGuard keys **only in a private tmpfs**, and tests Linux WireGuard and nftables. The script does not use `sudo`, modify host networking, add production routes, touch NetBird or contact an outside address. Temporary peer processes are terminated and the private tmpfs is unmounted during normal cleanup. The isolated mount is discarded on namespace exit even if the test is interrupted unexpectedly. No private keys or host traffic captures are committed or printed.

The script **never** downloads or installs tools and is **not automatically executed in GitHub Actions**. CI only checks its Bash syntax; privileged behavior requires an explicitly approved disposable development environment.

## Preconditions

- A nonroot Linux account that is authorized to create unprivileged user/network/mount namespaces and mount a private tmpfs.
- Linux WireGuard kernel support, plus `ip`, `nft`, `unshare`, `nsenter`, `ping`, `timeout`, `mount`, `umount`, `stat`.
- A locally installed, verified `wg` executable, or a verified distro-vendored binary supplied by absolute path via `WG_BIN`.
- Permission to run a short, disposable local laboratory test. Not a production VPS or a device with irreplaceable workloads.

Run the read-only prerequisite check first:

```sh
goreecloud-vpn-lab --json
```

The preflight may show that the current shell lacks `CAP_NET_ADMIN`, even when a fresh rootless user namespace can acquire that capability **only within its new private network namespace**. This does **not** grant privilege over the host network.

## Explicit manual execution

```sh
WG_BIN=/absolute/path/to/verified/wg bash tests/integration/wireguard_rootless_smoke.sh --run
```

With `wg` on PATH, `WG_BIN` can be omitted. Running without `--run` prints usage and exits without changing networking.

An **experimental separate opt-in mode** tests the GoreeCloud management-plane nftables ingress preview in the same rootless lab:

```sh
WG_BIN=/absolute/path/to/verified/wg bash tests/integration/wireguard_rootless_smoke.sh --run --policy-preview
```

This mode registers the actual lab-generated WireGuard public keys to a temporary SQLite management store on the lab’s 4 MiB private tmpfs, compiles ICMP default-deny/allow and TCP/UDP destination-port previews, checks them with `nft -c`, and applies them **only inside the receiving disposable namespace**. The basic socket probes demonstrate allowed TCP 8443 / UDP 5353 and denied TCP 8444 / UDP 5354 on the actual overlay. They do not test established-flow revocation, reverse-direction ACLs, or source spoofing. In the disposable namespace, a deliberately malformed `nft -f` replacement batch is rejected without removing the active deny; valid single-batch `flush chain`/`add rule` transactions subsequently update the dedicated test chain. This confirms a limited **kernel transaction property**, not production policy deployment or absence of a network outage. The test does not create a production network agent or handle connection tracking. See [nftables preview boundaries](NFT_INGRESS_PREVIEW.md).

A successful smoke test checks:

1. Layer-3 underlay communication through a veth pair between **two isolated network namespaces**.
2. An actual kernel WireGuard handshake and successful overlay ICMP traffic.
3. An nftables rule dropping a decrypted packet on the receiving WireGuard interface.
4. Restored overlay traffic after removal of the test rule.
5. Failed overlay traffic after removing the receiving peer's WireGuard public key.
6. Cleanup of interfaces, namespace processes, and temporary key storage.

### Observed development-laptop evidence (November 7, 2026)

The lab executed without root on the authorized laptop. All five packet/crypto assertions and normal cleanup passed. The local `wg` program came from Ubuntu `wireguard-tools` package version `1.0.20210914-1ubuntu4`, downloaded into a temporary directory; its SHA-256 matched the authenticated distribution package index: `19790a3203a12791bfaf622ea000780a7558de858766100d52f802079d44c400`. No system-wide package installation was performed.

**Limitations:** These are manually configured kernel interfaces, identities and nftables policy. The GoreeCloud management API did not provision the peers, translate policies into nftables, revoke them, or verify TLS and endpoint trust. A successful script does **not** satisfy the product's real data-plane, hostile-network, stability, multi-OS, recovery or production release gates. The test is skipped by CI and must be explicitly rerun in an authorized isolated lab for every applicable release.

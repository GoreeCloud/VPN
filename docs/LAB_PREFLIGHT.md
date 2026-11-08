# GoreeCloud VPN — isolated Linux lab preflight

**Maturity:** observation-only prerequisite checker. It is not a VPN agent, tunnel setup tool, packet test, deployment script, or authorization to alter device networking.

GoreeCloud VPN needs an isolated, disposable Linux environment before any real WireGuard tunnel or deny-by-default firewall work can be accepted. The development laptop's current state alone cannot establish that such a lab is safe.

## Run

From an installed source checkout:

```sh
python -m goreecloud_vpn.lab_preflight --json
```

After local installation, the equivalent command is:

```sh
goreecloud-vpn-lab --json
```

Use `--strict` to return exit code **2** whenever an observable prerequisite is blocked or unverified. The default command returns exit code **0** after completing inspection, even when prerequisites are absent. This allows local inspection without presenting missing privileges as a software crash.

## Observations

The checker reads only executable availability and local kernel/process metadata. It does not invoke commands or enumerate existing interfaces, IPs, routes, DNS, neighbors, VPN peers, keys, containers, or firewall rules.

| Check | Meaning and limitation |
| --- | --- |
| Linux | The intended disposable network namespace test platform |
| `wg` | WireGuard configuration tool available on PATH |
| `ip` | Linux `iproute2` command available on PATH |
| `nft` | nftables userspace tool available on PATH |
| `unshare` | Namespace helper available on PATH |
| Effective CAP_NET_ADMIN | Capability observed in the current process only; actual use is not tested |
| Network namespace process entry | `/proc/self/ns/net` is visible; does **not** prove a new isolated namespace can be created |
| WireGuard kernel module | Module visible in `/sys/module` or `/proc/modules`; an absent module may instead be built into the kernel |

Reported prerequisite success is **not** a real VPN readiness certification. The output always declares `real_wireguard_tunnel_verified: false`, `packet_policy_enforcement_verified: false`, and `network_mutations_performed: false`.

## Required real-tunnel lab gates (not yet implemented)

1. Verify ownership of a **disposable** test target, with permission to change that target's network namespace and packet rules. No VPS or NetBird production involvement.
2. Capture test-environment state, dependency versions, teardown commands, failure recovery and rollback **before** touching privileged networking.
3. Use isolated devices or dedicated namespaces and individually generated ephemeral WireGuard keys. Never collect actual device private keys into source control or test logs.
4. Prove encrypted bidirectional traffic through a real WireGuard tunnel.
5. Prove wrong-key, unauthorized group, unauthorized port, wrong direction, revocation and control-plane outage traffic is **dropped by the kernel packet path**, not merely denied by the management API.
6. Verify that every interface, rule, route, process, secret and temporary test artifact is removed afterward, including after negative tests and failure injection.
7. Preserve exact source SHA, dependency versions and reproducible evidence before considering deployment.

This preflight intentionally performs **none** of these privileged steps. For the broader acceptance checklist see [the threat model](THREAT_MODEL.md) and [implementation roadmap](ROADMAP.md).

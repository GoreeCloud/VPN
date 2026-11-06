# Disposable WireGuard data-plane verification plan

**Status:** test specification only, not an implemented harness or evidence of working VPN connectivity. Tracks [P0 #1](https://github.com/GoreeCloud/VPN/issues/1) and enrollment review [#7](https://github.com/GoreeCloud/VPN/issues/7).

## Isolation and preflight

Use a disposable Linux VM or CI runner explicitly dedicated to networking tests, with two or more *new* network namespaces and synthetic endpoint-held WireGuard private keys. Never run the harness on a production gateway, NetBird/Tailscale node, shared VPS, or a host with important routes. Check `ip route` and `ip -6 route` for collisions before choosing an RFC1918 test subnet. Require `wireguard-tools`, kernel WireGuard support, `iproute2`, packet counters, and permission to create namespaces **inside that disposable runner only**. Fail closed or skip with a clear reason when prerequisites are missing. No fixed production IPs, credentials, or host firewall changes.

The future harness must create and destroy only resources tagged with its unique run ID; register cleanup before creating resources, trap termination, and check for leftover namespaces, links, routes, rules and processes. A failed cleanup is a failed test, not a success. Never flush a host firewall or rewrite a host default route.

## Acceptance matrix

| ID | Setup and stimulus | Independent observation required |
| --- | --- | --- |
| WG-01 | Two approved peers with distinct endpoint-generated keys; explicitly permit one TCP port and one UDP port | Fresh WireGuard handshake timestamps **and** transfer counters increase; TCP and UDP payloads arrive at the intended destination |
| WG-02 | Pending peer, revoked peer, unknown public key, and wrong key-possession proof, each separately | Enrollment denied; no active peer or permissive packet rule remains; protected payload cannot arrive |
| WG-03 | Rotate an approved endpoint's WireGuard key pair using a fresh endpoint-held private key; attempt a new handshake and protected payload with both the retired and replacement keys, including after agent restart | Replacement key establishes a fresh authenticated handshake and delivers only explicitly allowed payload; retired key cannot re-handshake or deliver protected packets, and no stale peer entry or policy binding remains (verify handshake state, packet capture and counters) |
| WG-04 | In a disposable three-peer topology, attempt to register a second approved key with a duplicate or overlapping tunnel address/AllowedIPs range; attempt source-address spoofing and traffic to another peer's protected address | Conflicting identity-to-address assignments are rejected or deterministically quarantined before activation; spoofed source traffic cannot reach an unauthorized destination, and packet captures plus `wg show` peer AllowedIPs and route snapshots prove no cross-peer delivery or permissive fallback |
| ZT-01 | Approved peers with no allow policy; attempt TCP, UDP, ICMP in both directions | Every probe blocked, confirmed by packet capture or enforcement counters, not merely API decision output |
| ZT-02 | Permit one directional TCP port and one UDP port; probe permitted ports, adjacent ports, reverse direction and ICMP | Only explicitly permitted flows arrive; all other probes denied |
| ZT-03 | In a disposable dual-stack topology, probe IPv6 TCP, UDP and ICMPv6 between approved peers with no IPv6 allow policy; repeat when IPv4 is explicitly allowed. If IPv6 is unsupported, attempt an IPv6 probe and verify that no alternate interface, route or fallback path delivers it | IPv6 payloads are denied independently of IPv4 grants, with packet capture/counters and namespace route/interface inspection; report SKIP with an explicit unsupported-platform reason only when the probe cannot be constructed |
| ZT-04 | Establish an allowed long-lived TCP connection and UDP flow, then delete the matching allow policy without disconnecting peers; send fresh payloads on the existing flows and attempt new flows | Both established and new flows stop delivering protected payloads within a specified, measured policy-convergence bound; verify enforcement and conntrack/state cleanup with packet captures or counters, not only policy API output |
| RV-01 | Revoke a peer while its allowed flow is active; retry packets and handshake renewal | Previously allowed data stops within a **specified, measured** maximum interval; stale peer/rules are removed |
| RV-02 | Disconnect controller before and after revocation; test expiry of previously issued authorization | Record actual disconnected behavior; require a documented fail-closed lease/expiry design before claiming bounded distributed revocation |
| FL-01 | Restart agents, reapply same policy twice, inject a failure midway through rule replacement | No fail-open interval; rules remain deterministic; restart and recovery produce no orphaned state |
| CL-01 | End normally and terminate mid-setup in a disposable runner | No test-created namespaces, links, routes, firewall rules or background processes remain; host baseline remains unchanged |

## Evidence required for each case

Record the exact commit SHA, runner/kernel and WireGuard versions, namespace topology and nonconflicting address selection, synthetic key *public* fingerprints (never private keys), commands, test timestamps, exit codes, packet capture/counter deltas, and cleanup/baseline comparison. Redact tokens and private keys from logs and CI artifacts. Mark each case PASS, FAIL or SKIP with reason; **management API decisions and generated peer stanzas are not packet-level proof**.

## Implementation gate

Implement this matrix as an opt-in integration test suite on an isolated development branch, with CI only on disposable, authorized runners. Review privileged network operations and cryptographic enrollment independently. Do not advertise VPN readiness, merge security-sensitive behavior, or touch live infrastructure based on this document alone.

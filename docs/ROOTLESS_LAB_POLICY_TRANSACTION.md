# GoreeCloud VPN — guarded rootless lab policy transaction

**Status:** experimental **test-only** helper, deliberately located under `tests/integration/` and NOT installed as a production executable. It does not implement an authenticated, least-privileged GoreeCloud VPN network agent or production traffic enforcement.

## What the disposable lab runs

The explicitly opt-in manual shell test `bash tests/integration/wireguard_rootless_smoke.sh --run --policy-preview` first enters fresh **rootless** user, network and mount namespaces, then starts two nested peers with real Linux kernel WireGuard interfaces and a dedicated lab-only nftables table.

The new `tests/integration/lab_policy_transaction.py` helper is invoked **only inside the receiving peer's private network namespace**. It:

1. Reuses the existing rootless user, network and mount namespace guard; refuses host-root execution, missing namespace proof, unapproved work directories or missing explicit `--run`.
2. Obtains only **public** `wg show wgB allowed-ips` text, never private keys or a full `wg show dump`.
3. Reads a temporary local management snapshot on private tmpfs and calls the read-only [single-snapshot preflight](OFFLINE_AGENT_PREFLIGHT.md). It selects only peers approved to send inbound traffic to the receiving target according to the directional policy. Any missing, unexpected or mismatched peer causes the helper to **refuse to apply policy**.
4. Checks the compiled TCP 8443 / UDP 5353 rules are identical to the separately generated disposable lab fixture. It verifies the dedicated receiving nftables INPUT chain already has an interface-wide drop before replacing it.
5. Submits one validated `nft -c -f -` syntax transaction and then an `nft -f -` transaction **without invoking a shell**. It checks the installed lab-only chain still has the terminal drop and expected TCP/UDP port matches.
6. Leaves the existing manually tested allowed/denied TCP, UDP, ICMP, spoofed source, reverse-direction and established-flow packet assertions to verify the kernel outcome.

### Adversarial refusal test

Before the normal application, the lab inserts an **unapproved extra WireGuard peer** into its receiving kernel interface. The helper must reject the unexpected public key. The lab compares `nft -j list chain` text before and after that rejected attempt to verify **no rules were changed**, then removes the unauthorized peer and performs a successful guarded transaction. This is strictly a **temporary lab test**, not a production attack attempt.

All temporary keys, snapshot files and checks live on a private tmpfs in the disposable mount namespace and are cleaned up. The helper uses fixed destination-interface/table identifiers, validates an owner-only directory, and cannot accept arbitrary nft programs from the caller.

## What this does NOT prove

- The management snapshot, key enrollment and input policies are **not cryptographically authenticated or signed**.
- A successful readback comparison inside the test does **not** independently attest a kernel, prevent time-of-check/time-of-use races, or guarantee any permissions outside the disposable namespace.
- No general privileged service, authenticated IPC, systemd supervision, hardware isolation, durable generation pinning, multi-user authorization or production rollback has been implemented.
- The policy preview remains **INPUT-only**. OUTPUT/FORWARD, IPv6 allow policies, broader routing/exit nodes, full conntrack cleanup and robust revocation still require independent engineering and review.
- This helper is not usable on a VPS, NetBird deployment, everyday Linux host or Android/Windows/macOS client. It is not distributed as a production entry point.

See [security requirements](../SECURITY.md), [release status](STATUS.md) and P0 [issue #22](https://github.com/GoreeCloud/VPN/issues/22). Never infer production readiness from a passing rootless kernel test.

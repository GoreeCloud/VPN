# GoreeCloud VPN — guarded rootless lab policy transaction

**Status:** experimental **test-only** helper, deliberately located under `tests/integration/` and NOT installed as a production executable. It does not implement an authenticated, least-privileged GoreeCloud VPN network agent or production traffic enforcement.

## What the disposable lab runs

The explicitly opt-in manual shell test `bash tests/integration/wireguard_rootless_smoke.sh --run --policy-preview` first enters fresh **rootless** user, network and mount namespaces, then starts two nested peers with real Linux kernel WireGuard interfaces and a dedicated lab-only nftables table.

The new `tests/integration/lab_policy_transaction.py` helper is invoked **only inside the receiving peer's private network namespace**. It:

1. Reuses the existing rootless user, network and mount namespace guard; refuses host-root execution, missing namespace proof, unapproved work directories or missing explicit `--run`.
2. Obtains only **public** `wg show wgB allowed-ips` text, never private keys or a full `wg show dump`.
3. Reads a temporary local management snapshot on private tmpfs and calls the read-only [single-snapshot preflight](OFFLINE_AGENT_PREFLIGHT.md). It selects only peers approved to send inbound traffic to the receiving target according to the directional policy. Any missing, unexpected or mismatched peer causes the helper to **refuse to apply policy**.
4. Checks the compiled TCP 8443 / UDP 5353 rules are identical to the separately generated disposable lab fixture. It verifies the dedicated receiving nftables INPUT chain already has an interface-wide drop before replacing it.
5. Submits one validated `nft -c -f -` syntax transaction and then an `nft -f -` transaction **without invoking a shell**. It validates the **entire ordered nftables JSON chain** before and after application: exact dedicated table/family/input-hook/priority, fixed peer /32 source and local destination, expected ICMP or TCP/UDP allow rules, and an unconditional final WireGuard-interface drop. Unexpected allow, unknown jump/verdict, extra rule, malformed JSON, bad ownership metadata or reordered rules causes rejection. The check ignores only volatile numeric rule handles and nftables version metadata; it is not a general nftables interpreter.
6. Leaves the existing manually tested allowed/denied TCP, UDP, ICMP, spoofed source, reverse-direction and established-flow packet assertions to verify the kernel outcome.

### Adversarial refusal test

Before the normal application, the lab inserts an **unapproved extra WireGuard peer** into its receiving kernel interface. The helper must reject the unexpected public key. The lab compares `nft -j list chain` text before and after that rejected attempt to verify **no rules were changed**. It then inserts a separate **unexpected accept rule** ahead of the final drop: the exact AST validator must refuse to apply any transaction, and before/after JSON must remain identical. The lab restores the known-good chain, **injects a forced failure after a valid policy update**, and verifies that the helper compiles/applies a separate **default-deny-only transaction** and exact-JSON verifies its final interface drop. A real ping must fail during the recovered deny state. Only then does the test restore the initial chain and allow a normal guarded transaction. This is strictly a **temporary lab test**, not a production attack attempt.

All temporary keys, snapshot files and checks live on a private tmpfs in the disposable mount namespace and are cleaned up. The helper uses fixed destination-interface/table identifiers, validates an owner-only directory, and cannot accept arbitrary nft programs from the caller.

## What this does NOT prove

- The management snapshot, key enrollment and input policies are **not cryptographically authenticated or signed**.
- A successful readback comparison inside the test does **not** independently attest a kernel, prevent time-of-check/time-of-use races, or guarantee any permissions outside the disposable namespace.
- No general privileged service, authenticated IPC, systemd supervision, hardware isolation, durable generation pinning, multi-user authorization or production rollback has been implemented. The parser intentionally expects the fixed two-peer lab fixture and rejects other nft versions/representations that do not match its strict shape; it is not production-ready or portable kernel attestation.
- There is still a **readback-to-apply time-of-check/time-of-use race**: a privileged or compromised namespace actor could change peer/chain state between validation and nft commit. In one controlled lab-only post-apply failure case, the helper attempts to restore a **compiler-generated default-deny transaction**, verifies the exact kernel rules, then returns failure; this is **not a durable production rollback protocol**. If the recovery transaction itself fails, the helper raises an error and cannot attest that the kernel is fail-closed. Kernel crash, process termination between operations, hostile concurrent modifications, restart recovery and all packet races are still untested.
- The policy preview remains **INPUT-only**. OUTPUT/FORWARD, IPv6 allow policies, broader routing/exit nodes, full conntrack cleanup and robust revocation still require independent engineering and review.
- This helper is not usable on a VPS, NetBird deployment, everyday Linux host or Android/Windows/macOS client. It is not distributed as a production entry point.

See [security requirements](../SECURITY.md), [release status](STATUS.md) and P0 [issue #22](https://github.com/GoreeCloud/VPN/issues/22). Never infer production readiness from a passing rootless kernel test.

## November 10, 2026 — bounded private lab fixture source

The optional rootless WireGuard test transaction now reads its three fixed fixture files only through a held private-directory descriptor and `O_NOFOLLOW|O_NONBLOCK` regular-file descriptors. It enforces ownership, no group/other access, single link, unchanged inode/size/timestamps, and strict ASCII with fixed caps: 64 KiB for `lab-state.json`, 256 bytes for `binding-source-id.txt`, and 64 KiB for `ports.replace.nft`. Errors remain fixed and redacted. Eight synthetic file-gate tests exercise symlinks, hardlinks, public permissions, FIFO, oversized and non-ASCII input; no nft or wg subprocess executes in these tests. The mount/namespace and exactly owned nft kernel chain checks are still mandatory on any **separately authorized isolated rootless lab**. This does not establish a production agent, signed intent, protected kernel networking or a successful live WireGuard packet test.

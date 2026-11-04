# Management inspection and policy diagnostics

These features inspect **local administrative records**, not live network traffic.
They do not start tunnels, query devices, verify reachability, enforce policy,
provide DNS, prove device key ownership, or measure WireGuard handshakes.
All inspection endpoints require the same administrator bearer token as peer
management. Do not expose the alpha API remotely. No new dependencies or database
schema changes are required.

## Local inspection CLI

Install the package with `python -m pip install -e .`. Start `goreecloud-vpn`
in one terminal using the existing development instructions. In another terminal,
set `GOREECLOUD_VPN_ADMIN_TOKEN` to that server's token, then run:

```sh
goreecloud-vpnctl status
goreecloud-vpnctl peers
goreecloud-vpnctl policies
goreecloud-vpnctl diagnostics
goreecloud-vpnctl dns
goreecloud-vpnctl events --limit 20 --kind peer_revoked
goreecloud-vpnctl plan PEER_UUID
goreecloud-vpnctl explain SOURCE_UUID TARGET_UUID tcp --port 22
goreecloud-vpnctl explain SOURCE_UUID TARGET_UUID icmp
```

Replace uppercase UUID placeholders with real peer IDs. Use the global
`--host 127.0.0.1 --port 8176` options **before** the command to change the
management address; the `explain --port` argument is the destination flow port.
The CLI accepts literal IPv4 loopback addresses only, uses a five-second socket
timeout, ignores proxy environment variables, and never follows redirects.
Tokens are read from the environment, not command-line arguments. CLI tokens must
be 32–4096 printable ASCII characters without spaces. JSON goes to stdout;
errors go to stderr with a nonzero exit code. Responses are capped at 1 MiB.
The CLI only inspects records; it has no enrollment, approval or network mutation
commands. `python -m goreecloud_vpn.cli` provides the same interface.

## Management status

`GET /api/v1/status` returns lifecycle counts, configured DNS domain, policy count,
preview DNS-record count, and per-group counts split by peer status. It contains
no peer public keys, administrative token or device endpoint addresses.

The address pool reports `capacity`, `allocated`, `available`, and
`out_of_pool_records`. Allocation starts at subnet offset 10 and ends before the
broadcast address; capacity is therefore the subnet size minus 11. Pending,
approved **and revoked** records consume addresses. Revocation does not recycle
an address. An out-of-pool count indicates metadata inconsistent with the current
pool (for example, restarting with a different subnet). Reporting this does not
repair the configuration or authorize a subnet change.

`wireguard_tunnels_active`, `data_plane_enforced`, and `dns_server_running` remain
false. `/healthz` remains a minimal public process check with no inventory data.

## Explain and simulate access

`POST /api/v1/access/explain` takes the same JSON as `/api/v1/access/check`:

```json
{"source_id":"SOURCE_UUID","target_id":"TARGET_UUID","protocol":"tcp","port":22}
```

The response contains `allowed`, `reason`, `matching_policy_ids`, and
`data_plane_enforced: false`. Reasons are evaluated in this order:

1. `peer_not_found`: either identity is absent.
2. `peer_not_approved`: either record is pending or revoked.
3. `self_access_denied`: source and target are the same approved record.
4. `matching_allow_policy`: one or more directional policies match; all matching
   policy IDs are returned in sorted order.
5. `default_deny`: no rule matches.

TCP/UDP require an integer port from 1–65535. ICMP requires an omitted or null
port. The existing `/access/check` response shape is unchanged and uses the same
evaluator. Neither an allowed decision nor an approved record proves device
identity or packet-level access enforcement.

`POST /api/v1/access/simulate` accepts `{"checks": [ ... ]}` with 1–100 such
queries, subject to the existing 16 KiB request limit. `results` preserves input
order. All queries use one peer/policy snapshot serialized with this store's
writers. If any query is invalid, the whole request returns HTTP 400, with no
partial results. No peers, policies or events are changed. This simulates queries
against **current rules**, not hypothetical rule edits. The store is intended
for one management server; this is not a distributed snapshot guarantee.

```sh
# checks.json contains {"checks": [...]} with real peer IDs
goreecloud-vpnctl simulate < checks.json
```

## Policy diagnostics

`GET /api/v1/policies/diagnostics` reports each rule's number of eligible ordered
source/target peer pairs, excluding pending/revoked peers and self-pairs.
Warnings identify `no_approved_source_members`, `no_approved_target_members`, or
`no_distinct_peer_pairs`. A rule with no eligible pairs may simply be waiting for
enrollment; diagnostics do not disable or delete it.

`duplicate_policy_sets` groups exactly equivalent directional source-group,
target-group, protocol and port-set rules. This is not general overlap analysis:
a TCP rule for ports 22 and 443 is not called a duplicate of a TCP/22-only rule.
Results do not measure actual connectivity, firewall state or performance.

## Lifecycle history pagination

`GET /api/v1/events` still defaults to the latest 200 events and
`tamper_proof: false`. It now also returns `next_before`, which is null at the end.
Optional query parameters:

| Parameter | Contract |
|---|---|
| `limit` | Integer 1–200, default 200 |
| `before` | Positive SQLite sequence number, exclusive upper bound |
| `peer_id` | Exact peer identity filter, 1–128 characters |
| `kind` | `peer_registered`, `peer_approved`, or `peer_revoked` |

Continue with `before=next_before`, preserving the other filters. New events
inserted during traversal appear above the cursor and do not duplicate older
pages; start again without a cursor to see them. Unknown identities return an
empty page. Unknown/duplicate parameters, blank values and invalid limits return
HTTP 400. Cursors are not transferable across databases. History remains local,
mutable administrative metadata, not tamper-proof auditing or traffic logging.

```sh
goreecloud-vpnctl events --limit 20 --peer-id PEER_UUID
# Reuse next_before from the response:
goreecloud-vpnctl events --limit 20 --peer-id PEER_UUID --before SEQUENCE
```

## Safety and delivery boundary

Changes are additive except for stricter validation of event query parameters
(which were previously ignored). No schema migration, service deployment,
privileged command, live VPN connection, host firewall or routing change is
included. Key-possession/security review and verified data-plane enforcement
remain separate prerequisites for a usable secure VPN. Do not treat these
inspection tools as completing those release gates.

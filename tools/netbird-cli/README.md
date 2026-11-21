# GoreeCloud NetBird management CLI

**Source:** GoreeCloud/VPN/tools/netbird-cli. **Executable:** gc-netbird (Python 3 standard library). **Target:** the fresh NetBird combined server over HTTPS at https://netbird.goreecloud.com. **Host:** VPS Mesh /home/ladamian/.local/bin/gc-netbird. **Status:** installed; 19 isolated transport/safety tests passed; owner-enrolled PAT authenticated via live GET, and approved additive group, private DNS zone/record and TCP/443 policy writes succeeded with API readback. The broad Default policy has now been explicitly disabled by the owner; the only enabled VPN peer access rule is the verified admin-device-to-VPS TCP/443 policy.

## Authentication and least privilege

The NetBird REST API uses the Authorization: Token <PAT> HTTP header. A NetBird owner can create a PAT in the dashboard under Users / Me, or create a dedicated service user with appropriate access. Use a limited-lifetime token when supported. Never put a token in chat, environment logs, CLI arguments, GitHub, or this document.

~~~sh
gc-netbird resources
gc-netbird doctor
gc-netbird login       # owner runs interactively in a private VPS terminal, hidden input
gc-netbird auth-check  # noninteractive safe test, prints no private peer data
~~~

Login verifies the PAT against the authenticated GET /api/peers endpoint before storing it in ~/.config/goreecloud/netbird-cli/pat, mode 0600 (parent mode 0700). Noninteractive Remote Desktop Commander requests cannot supply a hidden PAT; enroll once in a private interactive VPS shell before using the remote agent. The command gc-netbird logout --confirm-write removes the local PAT file only; revoke the issued PAT separately in NetBird.

## Reading from Remote Desktop Commander

The following are operational with the privately enrolled, authenticated PAT. Summaries minimize private data by default; --show-data displays additional fields with token-like values redacted; --output FILE stores the unredacted API response in a *new* mode-0600 file, never overwriting.

~~~sh
gc-netbird list peers
gc-netbird list groups
gc-netbird list policies
gc-netbird get policies VERIFIED_POLICY_ID --show-data
gc-netbird list setup-keys
gc-netbird list networks
gc-netbird list routes
gc-netbird list posture-checks
gc-netbird list dns-zones
gc-netbird list dns-nameservers
gc-netbird list events-audit
gc-netbird api GET /api/dns/zones/VERIFIED_ZONE_ID/records
gc-netbird api GET /api/networks/VERIFIED_NETWORK_ID/resources
gc-netbird list peers --output "$HOME/peers-private.json"
~~~

Independent of token enrollment, a *read-only* SQLite fallback on this VPS exposes only nonsecret locally stored names and IDs. This is not an alternative API or an authoritative interpretation of live network policy:

~~~sh
gc-netbird local-list peers
gc-netbird local-list groups
gc-netbird local-list policies
~~~

## Writing groups and policies with safeguards

Prepare request JSON in an owner-private file (group/other nonwritable). Copy the source examples and replace placeholder IDs with fresh, verified IDs from the authenticated API. The example policy permits only the selected admin source group to a selected VPS server group on TCP/443, but does not get installed automatically.

~~~sh
cp /path/to/repo/tools/netbird-cli/examples/admin-group.json "$HOME/admin-group.json"
chmod 600 "$HOME/admin-group.json"
gc-netbird create groups --data-file "$HOME/admin-group.json" --dry-run

# An approved live write requires two explicit flags:
gc-netbird create groups --data-file "$HOME/admin-group.json" --confirm-write --confirm-network-impact
gc-netbird list groups

cp /path/to/repo/tools/netbird-cli/examples/allow-adguard-443.policy.json "$HOME/adguard-policy.json"
chmod 600 "$HOME/adguard-policy.json"
# Edit the copied file to include real new-NetBird group IDs first.
gc-netbird create policies --data-file "$HOME/adguard-policy.json" --dry-run
gc-netbird create policies --data-file "$HOME/adguard-policy.json" --confirm-write --confirm-network-impact
gc-netbird list policies
~~~

Updates use HTTP PUT, not PATCH/merge. Read and save the original before updating a policy/group. Deletes are destructive and additionally require --confirm-delete:

~~~sh
gc-netbird update policies VERIFIED_POLICY_ID --data-file "$HOME/replacement-policy.json" --dry-run
gc-netbird update policies VERIFIED_POLICY_ID --data-file "$HOME/replacement-policy.json" --confirm-write --confirm-network-impact
gc-netbird delete groups VERIFIED_GROUP_ID --confirm-write --confirm-network-impact --confirm-delete
~~~

**A dry run validates input, allowed API paths and a body hash; it never sends network traffic and cannot verify whether IDs exist. It is not permission to change a live VPN.** All live writes require specific authorization and verification/rollback. Do not delete the default All group or policy without a tested replacement. For one-time setup key creation, gc-netbird requires --output to save the raw secret in a new private file; it will not print the secret to the Remote Desktop Commander output.

## Private DNS for AdGuard

The administrator-device group and a scoped custom DNS zone and A record have been created and read back; verify the VPS overlay address and policy before modifying these records further. Use NetBird custom DNS zones (not public Porkbun DNS) to map adguard.goreecloud.com to that freshly verified private address. The zone needs a validated distribution_groups list and enable_search_domain false. See https://docs.netbird.io/api/resources/dns-zones.

~~~sh
gc-netbird create dns-zones --data-file "$HOME/adguard-zone.json" --dry-run
gc-netbird api POST /api/dns/zones/VERIFIED_ZONE_ID/records --data-file "$HOME/adguard-record.json" --dry-run
# After explicit authorization, both --confirm-write and --confirm-network-impact are required.
~~~

The real Caddy site already requires a NetBird-private source IP and its private CA for HTTPS. DNS alone cannot prove private application access; test routing, NetBird policy and certificates end to end.

## Implementation and validation

The API CLI pins origin to https://netbird.goreecloud.com, refuses redirects and environment proxy forwarding, verifies TLS, disallows path traversal/unknown URL origins, bounds response/input size, requires JSON file inputs for mutations, redacts secret-like fields, and never overwrites private output files. The underlying NetBird API continues enforcing user or service-user permissions. The optional local-list uses read-only SQLite connections to the fresh VPS database and cannot modify identities or policies.

~~~sh
python3 -m py_compile tools/netbird-cli/gc-netbird.py
python3 -m unittest discover -v -s tools/netbird-cli -p 'test_*.py'
GC_NETBIRD_BIN="$HOME/.local/bin/gc-netbird" python3 -m unittest discover -v \
  -s "$HOME/.local/share/goreecloud/netbird-cli/tests" -p 'test_*.py'
~~~

**Google Drive canonical command reference — uploaded and read back:** [goreecloud-netbird-cli-commands.md](https://drive.google.com/file/d/1dwfxRtv6zYNqwvsKhp3OzAp3umpIiUvJ/view), under GoreeCloud/CLI Commands/Third-Party/. This is the operational CLI command registry entry, separate from GitHub source ownership. Keep both consistent as commands change.

Official docs: https://docs.netbird.io/api , https://docs.netbird.io/api/resources/groups , https://docs.netbird.io/api/resources/policies , https://docs.netbird.io/api/resources/dns-zones , https://docs.netbird.io/manage/mcp-server .

## Verified new-peer VPN acceptance and initial private DNS implementation

On November 20, 2026 (America/Chicago), the newly enrolled VPS and laptop connected directly over NetBird P2P, both reporting 1/1 peers connected. The laptop reached the AdGuard Home login page over its verified VPS overlay IP using a per-request `curl --resolve` override and the Caddy private CA certificate. HTTP 200 and TLS verification result 0 were observed. The public-address AdGuard route continued returning HTTP 404. This validates the private transport but **not** normal DNS resolution or the AdGuard account login.

The VPS owner-only directory `~/.local/share/goreecloud/netbird-cli/examples/` contains live-specific, private JSON proposals (their initial submissions are now completed): `admin-devices-live-proposal.json`, `adguard-private-zone-proposal.json` and `adguard-private-record-proposal.json`. Their local fields were prepared from the current fresh NetBird peer inventory and validated with `--dry-run` (no request sent). Public source templates `examples/adguard-private-zone.json` and `examples/adguard-private-record.json` contain only placeholders, not a real peer ID or private IP. The CLI now fails closed for live writes while any `REPLACE_...` placeholder remains.

The operator must privately enroll an authorized NetBird PAT with `gc-netbird login`, then read the existing resources, create only the approved administrator group, and replace its returned group ID in the private DNS zone payload. Create that zone with distribution limited to admin devices, then write a record using its returned zone ID and the verified new VPS overlay IP. Confirm that hostname resolution succeeds on the laptop. No API mutation, policy replacement, DNS zone creation or server-side setup-key revocation was executed in this phase.

The one-time VPS bootstrap key file and mount have been removed after the peer successfully reconnected from persistent state. Revoke the issued key in the NetBird dashboard. The initial Default All-to-All policy was **disabled after verifying the narrow replacement rule**, and is retained in disabled state for safe rollback. Live post-cutover tests proved HTTPS/443 still allowed and previously working ICMP now unavailable. The owner-private rollback payload can re-enable Default only with explicit confirmation.


## Authenticated management acceptance (verified November 20, 2026, America/Chicago)

`gc-netbird auth-check` succeeded on VPS Mesh using the owner-enrolled PAT stored privately as mode 0600. All live modifications were explicit, additive, and preceded by a dry-run: created a group containing only the authorized laptop; created an enabled private DNS zone scoped to that group; added one apex A record for `adguard.goreecloud.com` with the newly verified VPS overlay IP; and created an enabled unidirectional TCP/443-only allow rule from administrator devices to the VPS server group. Authenticated readback verified each resource. The current Default All-to-All policy was **not** disabled or deleted, so this is not yet an enforced least-privilege network.

Laptop verification without `--resolve`: NetBird managed DNS answers the private VPS IP via `wt0`; `curl --cacert` to `https://adguard.goreecloud.com/login.html` returned HTTP 200 with TLS verify result 0. The public Caddy route denies the same hostname with HTTP 404. The VPS and laptop remain connected over NetBird P2P.

Future API use must reuse the existing created resource IDs rather than rerun CREATE commands; the example JSON in public source remains intentionally non-deployable until identifiers are replaced. The approved private file records and verified CLI output are on VPS Mesh, not in Git. The PAT and other secrets were never copied to source, logs, or Drive.


## Authorized Default All-to-All policy cutover, validated on both peers

The owner explicitly directed **disable the Default All-to-All policy; keep only the verified administrator-to-VPS rule**. The existing `Default` object was preserved, but `enabled` was changed to `false` through authenticated `gc-netbird update policies` PUT after confirming the live narrow rule (administrator laptop group → VPS server group, unidirectional TCP/443). This avoids deleting the original object or making uncontrolled group/peer changes.

The original full policy API response, a checked disabled JSON payload, and a checked re-enable/rollback JSON payload are stored privately on VPS Mesh under `~/.local/share/goreecloud/netbird-cli/rollback/`. Each file is mode 0600. Both PUT payloads passed offline `--dry-run` validation. The rollback was **not executed**. The API update returned HTTP 200; authenticated GET and LIST showed `Default.enabled=false` and the scoped policy `enabled=true`.

From the laptop: `netbird status` stayed 1/1 Connected P2P; NetBird private DNS continued resolving the AdGuard hostname over the overlay; ordinary HTTPS to the AdGuard login page continued returning HTTP 200 with verified private TLS. Negative tests: ping to the VPS previously returned replies but produced 0/2 afterward; reverse-direction VPS-to-laptop ping produced 0/2; TCP/22 was unreachable (also potentially affected by listener availability). Public NetBird, Vikunja and Plane HTTPS remained healthy. Only TCP/443 is intended to be permitted by the remaining NetBird access rule, not by Caddy alone.

**Emergency restore only if explicitly approved:**

```sh
file="$HOME/.local/share/goreecloud/netbird-cli/rollback/20261120-default-policy-disable-reenable.json"
gc-netbird update policies VERIFIED_DEFAULT_POLICY_ID --data-file "$file" --dry-run
# Re-enabling this will allow broad All-to-All networking again:
gc-netbird update policies VERIFIED_DEFAULT_POLICY_ID --data-file "$file" --confirm-write --confirm-network-impact
```

Do not run the rollback merely to check it; dry-run and previously saved API evidence are sufficient unless a real incident demands restoration. The policy change does not revoke existing device identities or close public host/service ports outside NetBird.

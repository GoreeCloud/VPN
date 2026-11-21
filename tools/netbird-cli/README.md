# GoreeCloud NetBird management CLI

**Source:** GoreeCloud/VPN/tools/netbird-cli. **Executable:** gc-netbird (Python 3 standard library). **Target:** the fresh NetBird combined server over HTTPS at https://netbird.goreecloud.com. **Host:** VPS Mesh /home/ladamian/.local/bin/gc-netbird. **Status:** installed; local read-only SQLite inventory and 18 isolated transport/safety tests verified; authenticated API calls and production CRUD pending enrollment of a personal access token (PAT).

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

The following are fully operational once a valid PAT is enrolled. Summaries minimize private data by default; --show-data displays additional fields with token-like values redacted; --output FILE stores the unredacted API response in a *new* mode-0600 file, never overwriting.

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

After enrolling newly created VPS and laptop NetBird peers, verify the VPS overlay address and an admin-only network policy first. Use NetBird custom DNS zones (not public Porkbun DNS) to map adguard.goreecloud.com to that freshly verified private address. The zone needs a validated distribution_groups list and enable_search_domain false. See https://docs.netbird.io/api/resources/dns-zones.

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

The source and tests should also be synchronized into the canonical Google Drive GoreeCloud/CLI Commands/Third-Party/ folder, with VPS-specific commands under Hosts/ when Drive raw Markdown writing is accessible; a GitHub source file is not proof of Drive synchronization.

Official docs: https://docs.netbird.io/api , https://docs.netbird.io/api/resources/groups , https://docs.netbird.io/api/resources/policies , https://docs.netbird.io/api/resources/dns-zones , https://docs.netbird.io/manage/mcp-server .

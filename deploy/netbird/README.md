# NetBird VPS Mesh deployment — Docker + Caddy + VPN-only AdGuard

**Purpose:** Restore the existing NetBird self-hosted management identity and peer/policy database, run the server and dashboard in Docker, use the existing Caddy reverse proxy, and enable **private-only** access to AdGuard Home at `adguard.goreecloud.com`. These are source-managed, non-secret templates. The real runtime configuration contains protected secrets and must **never** be committed to this public repository.

## Current deployment checkpoint (November 20, 2026, America/Chicago)

- **Executed and verified:** restored a COPY of existing NetBird server state into a private owner-only VPS directory. SQLite integrity checks passed. Preserved historical peers/groups/policies, rather than registering an empty new account. The original migration source remains intact.
- **Executed and verified:** the NetBird combined server and dashboard were started with pinned Docker digests. Server API and OIDC, dashboard and Caddy public TLS endpoint returned HTTP 200. Caddy issued a public ACME certificate for `netbird.goreecloud.com`. The existing Vikunja, Plane and Stirling public health endpoints remained HTTP 200.
- **Executed and verified:** retained Caddy backups and added the NetBird management route using h2c for gRPC. Restrained NetBird's `trustedPeers` and `trustedHTTPProxies` to the verified Caddy container IP, suppressing the prior default-route trust warning.
- **Executed and verified:** added an AdGuard Caddy site with `tls internal`, a `100.64.0.0/10` NetBird-only source matcher and an HTTP 404 response for other sources. TLS was validated using the public certificate of the private CA; a forced public-IP request returned **404**, not the AdGuard login page. No Porkbun public AdGuard DNS record was added.
- **Prepared and validated only:** the separate NetBird VPS peer Docker Compose and an interactive setup-key enrollment script. **The peer container is not yet running** because no new setup key has been provided. The laptop's pre-existing NetBird client also reports `NeedsLogin`. Consequently, neither the VPS's live NetBird private IP, private overlay reachability, nor end-to-end AdGuard login is currently proven.
- **Pending:** owner-authenticated NetBird SSO/login, one-time VPS peer enrollment, access-policy and private DNS acceptance, and browser handling of private CA trust. Do not claim full VPN operational acceptance until those are tested.

## Prerequisites and protected input

The verified VPS is `goreecloud-vps-mesh`, with Docker Compose and the existing `goreecloud-temp-caddy` attached to the external Docker network `goreecloud-temp_default`. The original NetBird `config.yaml` contains cryptographic identity and auth values. Preserve those values from an authorized encrypted backup or a verified existing installation. **Never generate replacement auth/encryption keys to "restore" established peer identities.** This template deliberately does not include `config.yaml`, application databases, or setup keys.

```sh
# Authorized VPS operator; use an owner-only work directory.
mkdir -p -m 700 "$HOME/goreecloud-netbird"
cd "$HOME/goreecloud-netbird"
# Place these reviewed source templates here and copy existing protected
# config.yaml and data/ FROM VERIFIED RESTORE STATE; never from public Git.
chmod 600 config.yaml
chmod 700 data/
cp dashboard.env.example dashboard.env
chmod 600 dashboard.env
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml up -d --no-build
docker compose -f docker-compose.yml ps
```

Do not run the server deployment command on an already running installation merely to replay this reference. On an existing deployment, inspect the current running state first and plan changes with backup and rollback.

## Private VPS peer enrollment (owner action required)

At [the existing NetBird dashboard](https://netbird.goreecloud.com), authenticate with the restored user account, go to **Settings → Setup Keys**, create a **one-off** key limited to enrollment of one VPS peer, and select the appropriate existing server groups. Save the key privately, then in an interactive VPS terminal run:

```sh
cd "$HOME/goreecloud-netbird"
./enroll-vps-peer.sh
docker exec goreecloud-netbird-client netbird status
ip -br addr | grep -E 'wt0|netbird'    # Verify actual overlay interface/address
```

The helper prompts with hidden input; it **does not accept a key on argv**, commit it, or print it. The setup key is saved as an owner-only file for the first startup; after successful persistent enrollment, revoke it in NetBird and replace Compose with a no-key bootstrap configuration before deleting it. Docker client capabilities and host networking affect host network/firewall state; confirm change-control and policies before running.

On the laptop, use the existing NetBird client and complete SSO sign-in through the same self-hosted domain:

```sh
netbird up --management-url https://netbird.goreecloud.com --admin-url https://netbird.goreecloud.com
netbird status -d
```

Do not paste login URLs, cookies, setup keys or private tokens into chats or logs. Check NetBird's effective access-control policy: a laptop in `admin-devices` or another approved admin group must be permitted to reach the VPS peer on TCP/443; family groups should not automatically get DNS administration rights. The original nine policies may or may not already permit this. Confirm with live NetBird policy/API evidence and a real allowed/denied connection test.

## Private DNS: `adguard.goreecloud.com` → verified VPN IP

**Do not publish the AdGuard hostname to the VPS public IP.** After server peer enrollment, verify its currently assigned `100.64.0.0/10` NetBird address. In NetBird's **Networking → DNS → Zones**, create a **Custom Zone** narrowly scoped to `adguard.goreecloud.com` and an **apex A record** also named `adguard.goreecloud.com` whose content is that verified address. Assign the zone to the approved administrator-device group(s) only; disable search-domain expansion. Confirm this does not shadow the rest of `goreecloud.com` and that peers have NetBird managed DNS enabled. The API supports an A record FQDN that matches the zone domain; if the UI does not support an apex record, use NetBird's documented authenticated API with a least-privilege administrative token, not a database mutation.

Verify on a connected, authorized laptop:

```sh
getent ahostsv4 adguard.goreecloud.com
netbird status -d
curl --cacert "$HOME/.local/share/goreecloud/private-adguard-tls/root.crt" \
  --output /dev/null --write-out '%{http_code}\n' \
  https://adguard.goreecloud.com/login.html
```

Successful application access requires all of: enrolled peer, correct routing/policies, correctly distributed DNS, TLS trust, Caddy proxy and real AdGuard account authentication. The expected unauthenticated login page response is HTTP 200, but this has **not** yet been observed over NetBird.

## Private HTTPS and trusted certificates

The AdGuard site uses Caddy's internal CA because the private-only hostname does not exist in public DNS. This is **not** a publicly trusted certificate. A copy of the *public root certificate only* (never a private CA key) has been securely transferred to the authorized laptop's owner-only path `~/.local/share/goreecloud/private-adguard-tls/root.crt`, and its SHA256 certificate fingerprint was cross-checked against VPS output. No operating-system or browser trust-store changes were made. Use `curl --cacert` for bounded tests. If the founder chooses browser trust, review the trust implications of any CA imported into the browser before accepting it; importing a local root globally can authorize that CA for more than just AdGuard.

## Verification and recovery commands

```sh
cd "$HOME/goreecloud-netbird"
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.peer.yml config --quiet
curl --fail --silent --show-error --max-time 8 -o /dev/null \
  https://netbird.goreecloud.com/oauth2/.well-known/openid-configuration
docker exec goreecloud-temp-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
curl --silent --show-error --max-time 8 -o /dev/null --write-out '%{http_code}\n' \
  https://vikunja.goreecloud.com/api/v1/info
```

The runtime Caddy snapshots are stored privately as `Caddyfile.before-netbird-20261120` and `Caddyfile.before-adguard-vpn-20261120` in the operator's private working directory. Restoring either file requires verifying the source/target identities and current operator changes first; restoring an old snapshot blindly can **delete newer routes**. Before any rollback, preserve the current file and service state, validate the candidate and reload Caddy once. NetBird state recovery requires the original encrypted backup, original auth/encryption settings, file permissions and compatibility review; the presence of copies does not constitute a rehearsed restore drill.

Do not use `docker compose down --volumes`, remove host firewall rules, wipe the restored SQLite databases or expose the AdGuard management port to the public internet as a troubleshooting shortcut.

## Sources, provenance and boundaries

- [Official NetBird Caddy combined-container proxy reference](https://docs.netbird.io/selfhosted/external-reverse-proxy)
- [Official NetBird Docker client](https://docs.netbird.io/get-started/install/docker)
- [Official Custom DNS Zones](https://docs.netbird.io/manage/dns/custom-zones)
- [Official private NetBird control-plane advice](https://docs.netbird.io/selfhosted/maintenance/private-management-plane)
- [GoreeCloud governing Drive instruction](https://docs.google.com/document/d/1W7eCxfSEw1_fpK7wSw8gfeHHCIJ8IrBE/edit)

This is a public-source operating reference, not the canonical Google Drive command register and not the private live configuration. Synchronize verified CLI commands into `GoreeCloud/CLI Commands/Third-Party/` and host-specific notes into `GoreeCloud/CLI Commands/Hosts/` when canonical raw Markdown editing is available. **No confidential credentials, private CA keys, or restored user data belong in Git.**

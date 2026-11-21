# Fresh NetBird VPN on VPS Mesh

**Implementation:** entirely new self-hosted NetBird Docker installation with an existing Caddy reverse proxy, a new embedded identity provider, fresh keys, a fresh empty management database, and a separate VPS peer to be enrolled after initial administrator login. No prior NetBird identities, groups, policies, peers, setup keys or databases are imported.

**Source owner:** GoreeCloud/VPN. **Runtime owner:** authorized VPS Mesh operator. This directory contains only reproducible non-secret source and documentation; do not commit real deployment configs, databases, certificates, recovery data or passwords.

## Fresh-install authentication compatibility

**Fixed November 20, 2026:** NetBird's combined server requires `server.auth.owner.password` to be a **bcrypt hash**. Supplying a plaintext password causes an OAuth login HTTP 500 with the upstream error "hashedSecret too short to be a bcrypted password", even while the public dashboard and OIDC metadata return HTTP 200. The source bootstrap now hashes a freshly generated owner password using pinned `bcrypt==4.2.0`, stores only the bcrypt hash in `config.yaml`, and writes the human-entered plaintext password **solely** to an owner-only `credentials/initial-admin-password` file. A test exercises the generated hash, compares it to the private password, and ensures neither application config nor logs expose plaintext. The deployed fresh server's bcrypt hash was corrected with NetBird's own `admin user change-password --password-file -` command; fresh management store remains empty (0 accounts/peers) until first login. OIDC and instance API health returned HTTP 200 after a server restart. Interactive login success is not yet established without a user sign-in.

To reproduce a fresh bootstrap in a private Python virtual environment, install the pinned dependency first:

```sh
python3 -m venv .venv-netbird-bootstrap
. .venv-netbird-bootstrap/bin/activate
python3 -m pip install -r /path/to/repo/deploy/netbird/requirements-bootstrap.txt
```

Do not embed a plaintext password in config, invoke a password-changing CLI with `--password` on argv, or upload a password-bearing file to GitHub. The existing private password-file repair method is for an operator explicitly recovering an incorrectly seeded **fresh** local IdP; do not recreate or restore historic databases.

## Live state — 2026-11-20 (America/Chicago)

| Area | Actual observation |
| --- | --- |
| NetBird combined server / dashboard | Running in Docker from immutable image digests, using an independently generated fresh config/data directory |
| Previous restored runtime | Containers stopped and removed; restored **deployment directory deleted** after validating mounts of the fresh deployment |
| Management store | New SQLite store passed integrity check; **0 management accounts, 0 management users, 0 peers, 0 groups, 0 policies, 0 setup keys** at pre-login checkpoint |
| Embedded local identity | A newly generated private bootstrap owner password was initially seeded as plaintext (triggering HTTP 500 login); corrected to validated bcrypt via NetBird's supported CLI and fixed in bootstrap source. **First authenticated sign-in remains unverified.** |
| NetBird dashboard, public TLS / OAuth2 discovery | HTTP 200 at `https://netbird.goreecloud.com`; existing Caddy TLS and upstream routes reused |
| STUN UDP/3478 | Verified responding during earlier control-plane tests; **repeat after fresh replacement before accepting final peer connections** |
| Existing application sites | Vikunja, Plane, Stirling PDF HTTP 200 after NetBird cutover |
| AdGuard via existing Caddy | Caddy internal TLS + `remote_ip 100.64.0.0/10` matcher; forced public-IP request was denied with HTTP 404, verified against Caddy local public root |
| VPS NetBird peer / laptop peer | **Not yet enrolled** into this new network; the old client login/profile cannot authenticate to the new management identity without new enrollment |
| NetBird private DNS | **Not yet established**; only after peer enrollment, resolve `adguard.goreecloud.com` to the *new* live VPS overlay IP |
| Historical migration archive | Separate old historical files exist under a migration archive **outside the running deployment**. They were not imported or mounted. Destructive removal of that pre-existing archival material is a separate retention decision |

No authenticated end-to-end AdGuard access is claimed yet. The new admin is not a migrated identity: use the newly generated password as documented below.

## Reproduce a clean install

Run on an authorized host, in a directory that does **not** exist. Identify the *current* private Docker IP of your existing Caddy container; reject stale addresses. The script fails closed rather than reusing an existing folder.

```sh
python3 bootstrap-fresh.py \
  --directory "$HOME/goreecloud-netbird-fresh" \
  --domain netbird.goreecloud.com \
  --owner-email '<ADMIN_EMAIL>' \
  --trusted-proxy-ip '<VERIFIED_CADDY_DOCKER_IP>'
cd "$HOME/goreecloud-netbird-fresh"

# Copy reviewed source-owned Compose templates; no restored database is needed.
cp /path/to/repo/deploy/netbird/docker-compose.yml .
docker compose config --quiet
docker compose up -d --no-build
```

The helper generates **new** 256-bit database encryption material, relay authentication material, and a strong owner password with Python's cryptographic random generator, then bcrypt-hashes that password before writing it to the server configuration. It creates an empty `data/` directory. Secret files are mode `0600`, directories `0700`. It prints no passwords/tokens. This script is **not** needed to replay the already-running deployment. Docker Compose is pinned by immutable digest. Restart with the existing preserved *new* store; do not regenerate keys after adoption or accidentally start a second concurrent SQLite server.

### First login without restored credentials

The bootstrap email is specified by the owner (the active installation uses the verified administrative email). The freshly generated password lives **only in the private VPS runtime**:

```sh
# Run on your authorized laptop using your correct SSH private key:
ssh -i ~/.ssh/<VERIFIED_LAPTOP_SSH_KEY> -o IdentitiesOnly=yes \
  '<VPS_USER>@<VPS_HOST>' \
  'cat "$HOME/goreecloud-netbird-fresh/credentials/initial-admin-password"'
```

Enter the generated password into [the new NetBird dashboard](https://netbird.goreecloud.com). This is intentionally not a public setup wizard with an unauthenticated owner-claim window. The first sign-in must be verified before making claims about new management accounts. On first successful sign-in, configure MFA if supported, rotate the initial password, verify the current owner and its permissions, and remove the plaintext bootstrap password from the private config only **after verifying account creation and subsequent login**. Do not revoke/remove initial access prematurely. The file under `credentials/` also requires secure retirement/rotation. Never put passwords, PATs, setup keys or private IDs in a GitHub PR, ChatGPT or unredacted log.

### Enroll an entirely NEW VPS peer

The `docker-compose.peer.yml` template uses a new, empty `client-state/` and mounts a private, hidden-input one-off setup key file. It never imports old peer WireGuard identities. Do not run it until the new owner has signed in and created an authorized one-off setup key in the new dashboard:

```sh
cd "$HOME/goreecloud-netbird-fresh"
./enroll-vps-peer.sh
docker exec goreecloud-netbird-client netbird status
ip -br addr
```

The helper requires an actual private interactive TTY. After stable enrollment, remove the setup-key mount from the running client Compose (with a reviewed configuration change), revoke the setup key server-side and delete the local key file. Do not embed a key in Compose, environment logs, or argv. The host-network peer requires restricted Docker/admin privileges and changes the network namespace; review firewall, inbound rules, and NetBird policy before starting.

### Connect laptops and configure the private AdGuard hostname

An existing laptop NetBird client must be **enrolled in the new network**. Old setup keys and sessions are not valid for this new installation. On the laptop, create/select a separate new profile when appropriate, sign into this control plane, and verify its new address/peers. The user must complete first owner sign-in; do not authenticate an unspecified account automatically.

Then create appropriate admin-device and server peer groups, and a *narrow* NetBird policy allowing only authorized administrators to connect to the **newly enrolled VPS peer** on TCP 443. Do not retain an open default all-to-all policy merely for ease of testing.

Once the VPS peer's real overlay address is known, add the custom NetBird DNS zone `adguard.goreecloud.com` and an apex A record pointing to that verified address; assign DNS only to the approved admin-device groups. Do not publish an A record in public Porkbun DNS to the VPS public IP. This avoids exposing the AdGuard admin UI. Validate client DNS responses, NetBird peers, TCP/443, and actual AdGuard HTTPS login.

Caddy currently uses `tls internal` for AdGuard. The **public CA certificate only** can be copied from Caddy to an authorized client for a scoped `curl --cacert` test. No CA root should be trusted globally without an explicit browser/OS security decision.

## Verified status and recovery

```sh
cd "$HOME/goreecloud-netbird-fresh"
docker compose ps
docker compose config --quiet
docker exec goreecloud-temp-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
curl -fsS https://netbird.goreecloud.com/oauth2/.well-known/openid-configuration -o /dev/null
curl -fsS https://netbird.goreecloud.com/api/instance -o /dev/null
docker ps --format '{{.Names}}'
```

The deployed Caddy routes are **still** the NetBird public management domain and the separately protected VPN-only AdGuard domain. There are independently retained Caddy rollback snapshots under the new working directory `caddy-recovery/`, but restoring these blindly could remove intervening changes. A usable application backup requires fresh server data/secret preservation and an independent restore rehearsal; neither should import the retired historical NetBird dataset.

## Security and authority

NetBird is a third-party system; GoreeCloud VPN is a separate first-party future app. Caddy exposure, setup keys, and the embedded IdP fall under GoreeCloud Identity, GoreeShield privacy and Wardveil network controls. Use real facts to promote states: **configured** does not mean **enrolled**, **an HTTP 200** does not mean **authorized peer communication**, and **a private DNS plan** does not mean **DNS works**.

Official resources: [Quickstart](https://docs.netbird.io/selfhosted/selfhosted-quickstart), [Deployment configuration](https://docs.netbird.io/selfhosted/maintenance/configuration-files), [Custom DNS zones](https://docs.netbird.io/manage/dns/custom-zones), [Docker client](https://docs.netbird.io/get-started/install/docker), [External reverse proxy](https://docs.netbird.io/selfhosted/external-reverse-proxy), [Backups](https://docs.netbird.io/selfhosted/maintenance/backup).

Document exact verified CLI command forms in the canonical `GoreeCloud/CLI Commands/Third-Party/` and host environment specifics in `GoreeCloud/CLI Commands/Hosts/` when raw Markdown editing is available. The GitHub copy is the deployed **source and engineering reference**, not a substitute for canonical Google Drive operating records.

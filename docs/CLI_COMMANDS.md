# First-party GoreeCloud VPN CLI (development preview)

**Canonical registry target:** Google Drive `GoreeCloud/CLI Commands/GoreeCloud/`. This GitHub file is source-maintained documentation; a Google Drive copy has **not** been verified and must not be claimed synchronized until it exists there.

The CLI is **GoreeCloud VPN** `vpnctl`, not the unrelated third-party NetBird `gc-netbird`. All commands in this document operate only against a separately started, first-party developer control-plane, never the production NetBird VPS.

From the first-party repository's root:

```bash
go test -race ./...
go vet ./...
go build -o ./build/vpnd ./cmd/vpnd
go build -o ./build/vpnctl ./cmd/vpnctl
bash scripts/e2e-loopback.sh
```

Private one-time developer token and local key generation (no token or private key is printed):

```bash
./build/vpnctl init-admin --token-file "$HOME/.config/goreecloud/vpn/admin-token"
./build/vpnctl keygen --dir "$HOME/.local/share/goreecloud/vpn/my-device"
./build/vpnd --listen 127.0.0.1:8788 \
  --state-dir "$HOME/.local/share/goreecloud/vpn/control" \
  --token-file "$HOME/.config/goreecloud/vpn/admin-token" \
  --web-root ./web/dist
```

From an **independent** terminal, strictly local authenticated REST peer registry:

```bash
./build/vpnctl info
./build/vpnctl list
./build/vpnctl register --name my-device \
  --public-key-file "$HOME/.local/share/goreecloud/vpn/my-device/wg-public.key" --confirm
./build/vpnctl list
# New peer registrations are pending by default; after independently verifying
# the owner and public key, authorize a reviewed gateway export (not live access):
./build/vpnctl approve --id VERIFIED_32_CHAR_ID --confirm
# After reviewing the exact target peer ID:
./build/vpnctl revoke --id VERIFIED_32_CHAR_ID --confirm
```

The `vpnctl config-client` command can render a **private** WireGuard split-tunnel configuration file from local private/public key files, an assigned private /32 and an approved gateway endpoint. It requires explicit `--confirm` and a fresh `--output` in a private directory. The file is **not activated**. The CLI never starts an Android tunnel. Android now includes an independent opt-in user-consented WireGuard GoBackend app path; native runtime acceptance is still pending. The key/config export commands never activate an interface. A separate root-gated Linux vpnagent is available for expressly approved isolated tests only. Never run these scripts as root, provide admin tokens in command-line arguments, send a private WireGuard key to the server, or point these preview tools at the live NetBird management service.

## Gateway configuration and isolated Linux agent

The first-party `vpnctl config-gateway` command can produce a private mode-0600 development gateway configuration with `--dir`, `--peers-file`, `--listen-port`, `--output`, and `--confirm`. The peers JSON contains a list of objects such as `[{"public_key":"VERIFIED_32_BYTE_BASE64_PUBLIC_KEY","address":"10.77.0.2/32"}]`; never use example placeholders for an actual gateway.

From the first-party repository root on a disposable test machine:

~~~sh
go build -o ./build/vpnagent ./cmd/vpnagent
./build/vpnctl keygen --dir "$HOME/.local/share/goreecloud/vpn/gateway"
chmod 600 "$HOME/.local/share/goreecloud/vpn/gateway/peers.json"
./build/vpnctl config-gateway --dir "$HOME/.local/share/goreecloud/vpn/gateway" --peers-file "$HOME/.local/share/goreecloud/vpn/gateway/peers.json" --listen-port 51820 --output "$HOME/.local/share/goreecloud/vpn/gateway/gateway.conf" --confirm
./build/vpnagent --action plan --private-key-file "$HOME/.local/share/goreecloud/vpn/my-device/wg-private.key" --gateway-public-key-file "$HOME/.local/share/goreecloud/vpn/gateway/wg-public.key" --address 10.77.0.2/32 --endpoint vpn.example.test:51820
bash scripts/test_linux_agent_plan.sh
~~~

The `plan` action is read-only and unprivileged; no interface is installed. The optional Linux `--action apply` requires root, `--confirm-apply`, and `--acknowledge-network-impact` and can alter the route to the fixed 10.77.0.0/24 test prefix. It must only run after explicit authorization on an isolated test host, never on the live NetBird production VPS. The separately confirmed `--action stop --confirm-stop --acknowledge-network-impact` checks an agent-owned marker before deleting gcvpn0. Neither action has been executed in this implementation phase.


## Current registry snapshot for gateway review

After registering device public keys with vpnctl, export a new private gateway input derived from the authenticated, current peer registry:

    ./build/vpnctl export-peers --api http://127.0.0.1:8788 --output "$HOME/.local/share/goreecloud/vpn/gateway/current-peers.json" --confirm
    ./build/vpnctl config-gateway --dir "$HOME/.local/share/goreecloud/vpn/gateway" --peers-file "$HOME/.local/share/goreecloud/vpn/gateway/current-peers.json" --output "$HOME/.local/share/goreecloud/vpn/gateway/review.conf" --confirm

This is a mode-0600 **no-overwrite** peer snapshot containing only administrator-approved, non-revoked public keys and valid 10.77.0.x/32 assigned addresses. It rejects malformed and duplicate records. It DOES NOT install the gateway config or enforce revocation in a live interface. After revoke, regenerate and independently apply a reviewed gateway configuration, and verify actual packet denial before claiming enforcement. The manual --peers-file path remains an explicit operator option but is not authoritative when it differs from the current registry.


**Exclusive server state:** The local vpnd process creates a private mode-0600 state.lock file under its owner-private state directory. A second vpnd using the same directory fails instead of risking lost peer approvals or revocations. Stop and inspect the owning process; never delete the lock file to bypass a running owner. Existing pending identities remain pending across restarts.


## Gateway-local firewall policy preview — never automatically applied

Create a reviewed private JSON list of gateway-local service grants, such as an approved public key permitted to access TCP 443:

    [{"public_key":"VERIFIED_APPROVED_PUBLIC_KEY_BASE64","protocol":"tcp","port":443}]

Store the list in a newly created owner-private (0600) file in a 0700 directory, replacing the illustrative key with an actual verified public key. Then:

    ./build/vpnctl config-acl --peers-file "$HOME/.local/share/goreecloud/vpn/gateway/current-peers.json" --rules-file "$HOME/.local/share/goreecloud/vpn/gateway/service-rules.json" --output "$HOME/.local/share/goreecloud/vpn/gateway/review-acl.nft" --confirm

The command fails if a service permission references any key absent from the current approved peer snapshot. Empty rules mean **deny all VPN-origin gateway services and forwarding by default**. Protocols supported in the development renderer are tcp, udp and icmp (echo-request only); TCP/UDP must have a numeric 1–65535 port and ICMP must have none. No arbitrary subnet, full-tunnel, peer-to-peer or wildcard service grant is emitted.

**Never invoke nft on the live VPS from these examples.** The generated file is review material, not an active firewall; correct host interface naming, rollback and boot restoration require a separately verified stage. The synthetic kernel GitHub Actions test uses a dedicated gateway namespace and is not live production policy enforcement.


## Encrypted registry metadata backup and offline restore

Use a distinct *owner-private* backup key, not a WireGuard private key or the control-plane administrator credential. The key must be preserved securely outside backup media. The commands never print its contents.

    ./build/vpnctl backup-keygen --backup-key-file "$HOME/.config/goreecloud/vpn/backup-key"
    ./build/vpnctl backup-registry --state-dir "$HOME/.local/share/goreecloud/vpn/control" --backup-key-file "$HOME/.config/goreecloud/vpn/backup-key" --output "$HOME/.local/share/goreecloud/vpn/registry-backup.gcvpnbak" --confirm
    ./build/vpnctl restore-registry --backup-file "$HOME/.local/share/goreecloud/vpn/registry-backup.gcvpnbak" --backup-key-file "$HOME/.config/goreecloud/vpn/backup-key" --state-dir "$HOME/.local/share/goreecloud/vpn/restored-staging" --confirm

The output path must not exist and its parent directory must be real and private (0700); snapshot and key files are mode 0600. Restore requires a **new, nonexistent state directory** under an existing private parent: it never overwrites a live state.json or starts vpnd. A clean readback and independent device authorization checks are required before any controlled recovery handoff. Retain the backup encryption key separately, or recovery is impossible. This feature protects registry metadata only, not device WireGuard private keys or any deployed server/network configuration.


## Native Linux read-only handshake observation

The Qt Quick Linux client contains a button that inspects **only** the dedicated gcvpn0 interface without requesting root or modifying routes. Under the hood it checks for /sys/class/net/gcvpn0 and, when the local system has the executable and permissions, uses fixed direct arguments equivalent to:

    /usr/bin/wg show gcvpn0 latest-handshakes

If that absolute path is unavailable, the app may use /usr/sbin/wg instead. Never copy peer public keys, private keys, full wg show output or device IPs into public issue logs. Exit failures and stale timestamps are reported as **unverified**, not as a functional VPN. This is documentation-only command behavior unless independently observed on the target Linux machine; the CI self-test uses synthetic data and does not execute a live wg command.

## Direct vpnd HTTP guard

The existing vpnd --listen host:port and optional --tls-cert/--tls-key configuration now requires exact TCP-bound Host and matching browser Origin for every request. Examples:

    ./build/vpnd --listen 127.0.0.1:8788 --state-dir PRIVATE_0700_STATE_DIR --token-file PRIVATE_0600_ADMIN_TOKEN
    curl --fail --max-time 3 http://127.0.0.1:8788/healthz

For a non-loopback listener, a separately provisioned and audited TLS certificate and key must be supplied; minimum negotiated TLS version is 1.3. Use only approved private endpoints, never assume a browser reverse proxy or externally exposed listener is safe. The direct-source request guard has a burst limit of 24 and refills two requests per second (HTTP 429 with Retry-After on exhaustion). Untrusted Host/Origin requests are rejected before authentication is evaluated. Curl is for synthetic localhost health tests, not production network acceptance.

**Verification status (2026-11-21 CST):** The host-bound Go handler, same-origin validation and rate-limit negative tests passed local Go unit/race tests and disposable localhost integration; the first-party VPN code is on a development PR. The Qt observer and Android development-profile guard still require their independently compiled CI checks before native acceptance. Drive's existing GoreeCloud/CLI Commands/GoreeCloud/ directory has no VPN.md entry; direct in-place canonical Markdown creation/update needs an authorized file upload reference, so this repository source reference has not yet been synchronized into the Drive registry.

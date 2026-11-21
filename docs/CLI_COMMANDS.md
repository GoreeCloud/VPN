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
  --web-root ./web
```

From an **independent** terminal, strictly local authenticated REST peer registry:

```bash
./build/vpnctl info
./build/vpnctl list
./build/vpnctl register --name my-device \
  --public-key-file "$HOME/.local/share/goreecloud/vpn/my-device/wg-public.key" --confirm
./build/vpnctl list
# After reviewing the exact target peer ID:
./build/vpnctl revoke --id VERIFIED_32_CHAR_ID --confirm
```

The `vpnctl config-client` command can render a **private** WireGuard split-tunnel configuration file from local private/public key files, an assigned private /32 and an approved gateway endpoint. It requires explicit `--confirm` and a fresh `--output` in a private directory. The file is **not activated**. There is **no** `vpnctl up`, `vpnctl connect`, `vpnctl route` or `VpnService` implementation in this stage. No command installs, routes, configures or launches an encrypted tunnel. Never run these scripts as root, provide admin tokens in command-line arguments, send a private WireGuard key to the server, or point these preview tools at the live NetBird management service.

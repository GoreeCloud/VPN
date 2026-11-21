#!/usr/bin/env bash
# GitHub-hosted Linux namespace integration ONLY. Never run on a user's host.
# Proves a real kernel WireGuard handshake and applied revocation in disposable namespaces.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${GITHUB_REPOSITORY:-}" != "GoreeCloud/VPN" ||
      "${RUNNER_OS:-}" != "Linux" || "$(id -u)" != "0" ]]; then
  echo "REFUSED: requires authorized GoreeCloud GitHub Actions Linux runner" >&2
  exit 2
fi
: "${VPNCTL:?compiled vpnctl binary required}"
: "${VPND:?compiled vpnd binary required}"
[[ -x "$VPNCTL" && -x "$VPND" ]] || { echo "Missing first-party CLI binaries" >&2; exit 2; }
for program in ip wg wg-quick nft ping python3 curl; do
  command -v "$program" >/dev/null || { echo "Missing $program" >&2; exit 2; }
done
umask 077
TMP="$(mktemp -d /tmp/gcvpn-wireguard-netns.XXXXXX)"
NGW="gcvpngw$$"
NCL="gcvpncl$$"
PID=""
cleanup() {
  set +e
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; fi
  ip netns del "$NCL" 2>/dev/null || true
  ip netns del "$NGW" 2>/dev/null || true
  case "$TMP" in /tmp/gcvpn-wireguard-netns.*) rm -rf -- "$TMP";; esac
}
trap cleanup EXIT

"$VPNCTL" init-admin --token-file "$TMP/admin/token" >/dev/null
"$VPNCTL" keygen --dir "$TMP/gateway" >/dev/null
"$VPNCTL" keygen --dir "$TMP/client" >/dev/null
"$VPND" --listen 127.0.0.1:18789 --state-dir "$TMP/state" \
  --token-file "$TMP/admin/token" > "$TMP/server.log" 2>&1 &
PID="$!"
for _ in {1..40}; do
  if curl --silent --show-error --fail --max-time 1 http://127.0.0.1:18789/healthz > /dev/null 2>&1; then break; fi
  sleep 0.1
done
curl --silent --show-error --fail --max-time 3 http://127.0.0.1:18789/healthz >/dev/null
"$VPNCTL" register --api http://127.0.0.1:18789 \
  --token-file "$TMP/admin/token" --name isolated-client \
  --public-key-file "$TMP/client/wg-public.key" --confirm > "$TMP/registered.json"
ID="$(python3 - "$TMP/registered.json" <<'PYID'
import json,sys
record=json.load(open(sys.argv[1],encoding="utf-8"))
assert record["address"]=="10.77.0.2/32"
print(record["id"])
PYID
)"
[[ "$ID" =~ ^[0-9a-f]{32}$ ]]

# Default-deny: new registration must not enter gateway configuration without
# explicit authenticated administrator approval.
"$VPNCTL" export-peers --api http://127.0.0.1:18789 --token-file "$TMP/admin/token"   --output "$TMP/gateway/pending.json" --confirm >/dev/null
python3 - "$TMP/gateway/pending.json" <<'PYPENDING'
import json,sys
assert json.load(open(sys.argv[1],encoding="utf-8")) == [], "Pending peer leaked into gateway"
PYPENDING
if "$VPNCTL" approve --api http://127.0.0.1:18789 --id "$ID"   --token-file "$TMP/admin/token" >/dev/null 2>&1; then
  echo "Approval without --confirm unexpectedly allowed" >&2; exit 1
fi
"$VPNCTL" approve --api http://127.0.0.1:18789 --id "$ID"   --token-file "$TMP/admin/token" --confirm >/dev/null
"$VPNCTL" export-peers --api http://127.0.0.1:18789 \
  --token-file "$TMP/admin/token" --output "$TMP/gateway/active.json" --confirm >/dev/null
"$VPNCTL" config-gateway --dir "$TMP/gateway" --peers-file "$TMP/gateway/active.json" \
  --output "$TMP/gateway/gateway.conf" --listen-port 51820 --confirm >/dev/null
# An approved key still cannot access ANY gateway service unless separately
# granted a narrow gateway-local ACL. Generate both reviewed policy variants.
printf '[]\n' > "$TMP/gateway/no-services.json"
chmod 600 "$TMP/gateway/no-services.json"
python3 - "$TMP/client/wg-public.key" "$TMP/gateway/icmp-rule.json" <<'PYACL'
import json,sys
key=open(sys.argv[1],encoding="utf-8").read().strip()
with open(sys.argv[2],"w",encoding="utf-8") as f:
    json.dump([{"public_key":key,"protocol":"icmp"}],f)
PYACL
chmod 600 "$TMP/gateway/icmp-rule.json"
"$VPNCTL" config-acl --peers-file "$TMP/gateway/active.json"   --rules-file "$TMP/gateway/no-services.json" --output "$TMP/gateway/deny.nft" --confirm > /dev/null
"$VPNCTL" config-acl --peers-file "$TMP/gateway/active.json"   --rules-file "$TMP/gateway/icmp-rule.json" --output "$TMP/gateway/allow-icmp.nft" --confirm > /dev/null

"$VPNCTL" config-client --dir "$TMP/client" \
  --gateway-public-key-file "$TMP/gateway/wg-public.key" \
  --address 10.77.0.2/32 --endpoint 198.18.0.1:51820 \
  --output "$TMP/client/client.conf" --confirm >/dev/null

# Host routing, interfaces, DNS, and firewall remain untouched outside namespaces.
ip netns add "$NGW"
ip netns add "$NCL"
ip link add vethgcvpn type veth peer name vethgccl
ip link set vethgcvpn netns "$NGW"
ip link set vethgccl netns "$NCL"
ip -n "$NGW" addr add 198.18.0.1/30 dev vethgcvpn
ip -n "$NCL" addr add 198.18.0.2/30 dev vethgccl
ip -n "$NGW" link set dev lo up
ip -n "$NCL" link set dev lo up
ip -n "$NGW" link set dev vethgcvpn up
ip -n "$NCL" link set dev vethgccl up
ip netns exec "$NCL" ping -c 1 -W 2 198.18.0.1 >/dev/null

# nft is invoked ONLY in the synthetic gateway namespace (never on the host).
ip netns exec "$NGW" nft -c -f "$TMP/gateway/deny.nft"
ip netns exec "$NGW" nft -c -f "$TMP/gateway/allow-icmp.nft"
ip netns exec "$NGW" nft -f "$TMP/gateway/deny.nft"
ip netns exec "$NCL" ping -c 1 -W 2 198.18.0.1 >/dev/null
ip netns exec "$NGW" wg-quick up "$TMP/gateway/gateway.conf" >/dev/null
ip netns exec "$NCL" wg-quick up "$TMP/client/client.conf" >/dev/null
# WireGuard can authenticate, but firewall must deny even an approved peer
# until an explicit service permission is applied.
if ip netns exec "$NCL" ping -c 1 -W 2 10.77.0.1 >/dev/null 2>&1; then
  echo "Approved identity bypassed default-deny gateway service ACL" >&2; exit 1
fi
LATEST="$(ip netns exec "$NCL" wg show client latest-handshakes | awk '{print $2}')"
[[ "$LATEST" =~ ^[0-9]+$ && "$LATEST" -gt 0 ]] || {
  echo "Real WireGuard handshake not verified" >&2; exit 1;
}

ip netns exec "$NGW" nft delete table inet goreecloud_vpn
ip netns exec "$NGW" nft -f "$TMP/gateway/allow-icmp.nft"
ip netns exec "$NCL" ping -c 2 -W 3 10.77.0.1 >/dev/null

# A different unregistered X25519 identity must not authenticate even from
# the same network namespace, address, endpoint and allowed IP route.
"$VPNCTL" keygen --dir "$TMP/rogue" >/dev/null
ip netns exec "$NCL" wg set client private-key "$TMP/rogue/wg-private.key"
if ip netns exec "$NCL" ping -c 1 -W 2 10.77.0.1 >/dev/null 2>&1; then
  echo "Unregistered key authenticated on the development gateway" >&2; exit 1
fi
ip netns exec "$NCL" wg set client private-key "$TMP/client/wg-private.key"
ip netns exec "$NCL" ping -c 2 -W 3 10.77.0.1 >/dev/null

# Verify the split route was not accidentally changed into a default route.
if [[ -n "$(ip -n "$NCL" route show default)" ]]; then
  echo "Client default route was unexpectedly modified" >&2; exit 1
fi

# A registry tombstone alone does not revoke access: explicitly apply a new gateway state.
"$VPNCTL" revoke --api http://127.0.0.1:18789 --id "$ID" \
  --token-file "$TMP/admin/token" --confirm >/dev/null
"$VPNCTL" export-peers --api http://127.0.0.1:18789 \
  --token-file "$TMP/admin/token" --output "$TMP/gateway/revoked.json" --confirm >/dev/null
"$VPNCTL" config-gateway --dir "$TMP/gateway" --peers-file "$TMP/gateway/revoked.json" \
  --output "$TMP/gateway/gateway-revoked.conf" --listen-port 51820 --confirm >/dev/null
# Export cannot grant old keys once revoked, even if the old ACL rules file
# still references them. Remove the last service grant.
if "$VPNCTL" config-acl --peers-file "$TMP/gateway/revoked.json"   --rules-file "$TMP/gateway/icmp-rule.json" --output "$TMP/gateway/invalid.nft" --confirm >/dev/null 2>&1; then
  echo "Revoked key was accepted as firewall ACL member" >&2; exit 1
fi
"$VPNCTL" config-acl --peers-file "$TMP/gateway/revoked.json"   --rules-file "$TMP/gateway/no-services.json" --output "$TMP/gateway/deny-revoked.nft" --confirm >/dev/null
ip netns exec "$NGW" nft delete table inet goreecloud_vpn
ip netns exec "$NGW" nft -f "$TMP/gateway/deny-revoked.nft"
ip netns exec "$NGW" wg-quick strip "$TMP/gateway/gateway-revoked.conf" > "$TMP/gateway/stripped.conf"
ip netns exec "$NGW" wg syncconf gateway "$TMP/gateway/stripped.conf"
[[ -z "$(ip netns exec "$NGW" wg show gateway peers)" ]] || {
  echo "Revoked identity remains configured on gateway" >&2; exit 1;
}
if ip netns exec "$NCL" ping -c 1 -W 2 10.77.0.1 >/dev/null 2>&1; then
  echo "Revoked peer still has packet-level access" >&2; exit 1
fi
echo "PASS: isolated Linux namespaces: first-party configs, kernel WireGuard handshake, wrong-key denial, default-deny service firewall with explicit allow, no default route, applied revocation and denied traffic"

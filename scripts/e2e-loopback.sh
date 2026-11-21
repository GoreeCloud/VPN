#!/usr/bin/env bash
# Disposable localhost-only control-plane acceptance. Does not contact NetBird or VPS.
set -euo pipefail
ROOT="$(pwd)"
TMP="$(mktemp -d /tmp/goreecloud-vpn-e2e.XXXXXX)"
chmod 700 "$TMP"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  case "$TMP" in /tmp/goreecloud-vpn-e2e.*) rm -rf -- "$TMP" ;; esac
}
trap cleanup EXIT

go build -o "$TMP/vpnd" "$ROOT/cmd/vpnd"
go build -o "$TMP/vpnctl" "$ROOT/cmd/vpnctl"
"$TMP/vpnctl" init-admin --token-file "$TMP/admin/token"
"$TMP/vpnctl" keygen --dir "$TMP/client" >/dev/null
"$TMP/vpnctl" keygen --dir "$TMP/gateway" >/dev/null
python3 - "$TMP/client/wg-public.key" "$TMP/gateway/peers.json" <<'PY'
import json,sys
key=open(sys.argv[1],encoding="utf-8").read().strip()
with open(sys.argv[2],"w",encoding="utf-8") as f:
    json.dump([{"public_key":key,"address":"10.77.0.2/32"}],f)
PY
chmod 600 "$TMP/gateway/peers.json"
"$TMP/vpnctl" config-gateway --dir "$TMP/gateway" --peers-file "$TMP/gateway/peers.json" \
  --output "$TMP/gateway/gateway.conf" --listen-port 51820 --confirm >/dev/null
[[ "$(stat -c %a "$TMP/gateway/gateway.conf")" == "600" ]]
grep -q 'AllowedIPs = 10.77.0.2/32' "$TMP/gateway/gateway.conf"
"$TMP/vpnctl" config-client --dir "$TMP/client" \
  --gateway-public-key-file "$TMP/gateway/wg-public.key" --address 10.77.0.2/32 \
  --endpoint vpn.example.test:51820 --output "$TMP/client/gc-vpn.conf" --confirm >/dev/null
[[ "$(stat -c %a "$TMP/client/gc-vpn.conf")" == "600" ]]
grep -q 'AllowedIPs = 10.77.0.0/24' "$TMP/client/gc-vpn.conf"
"$TMP/vpnd" --listen 127.0.0.1:18788 --state-dir "$TMP/state" \
  --token-file "$TMP/admin/token" --web-root "$ROOT/web/dist" >"$TMP/server.log" 2>&1 &
PID="$!"
for _ in {1..30}; do
  if curl -sSf --max-time 1 http://127.0.0.1:18788/healthz > /dev/null; then break; fi
  sleep 0.1
done
curl -sSf --max-time 3 http://127.0.0.1:18788/healthz | grep -q '"status":"ok"'
UNAUTH="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18788/v1/peers)"
[[ "$UNAUTH" == "401" ]] || { echo "Unauthenticated peer read was not denied"; exit 1; }
curl -sSf --max-time 3 http://127.0.0.1:18788/ | grep -q 'GoreeCloud VPN'
ASSET="$(curl -sSf --max-time 3 http://127.0.0.1:18788/ | grep -oE '/assets/[^"]+\.js' | head -n1)"
[[ "$ASSET" == /assets/* ]] || { echo "Missing compiled React entrypoint"; exit 1; }
curl -sSf --max-time 3 "http://127.0.0.1:18788$ASSET" | grep -q 'GoreeCloud'
# Assets outside the approved bundle must not be exposed.
[[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18788/go.mod)" == "401" ]]
"$TMP/vpnctl" info --api http://127.0.0.1:18788 --token-file "$TMP/admin/token" >/dev/null
"$TMP/vpnctl" register --api http://127.0.0.1:18788 --name "isolated-test" --public-key-file "$TMP/client/wg-public.key" \
  --token-file "$TMP/admin/token" --confirm >"$TMP/registered.json"
ID="$(python3 - "$TMP/registered.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8"))
assert p["address"]=="10.77.0.2/32"
print(p["id"])
PY
)"
[[ "$ID" =~ ^[0-9a-f]{32}$ ]]

# Default-deny: new registration must not enter gateway configuration without
# explicit authenticated administrator approval.
"$TMP/vpnctl" export-peers --api http://127.0.0.1:18788 --token-file "$TMP/admin/token"   --output "$TMP/gateway/pending.json" --confirm >/dev/null
python3 - "$TMP/gateway/pending.json" <<'PYPENDING'
import json,sys
assert json.load(open(sys.argv[1],encoding="utf-8")) == [], "Pending peer leaked into gateway"
PYPENDING
if "$TMP/vpnctl" approve --api http://127.0.0.1:18788 --id "$ID"   --token-file "$TMP/admin/token" >/dev/null 2>&1; then
  echo "Approval without --confirm unexpectedly allowed" >&2; exit 1
fi
"$TMP/vpnctl" approve --api http://127.0.0.1:18788 --id "$ID"   --token-file "$TMP/admin/token" --confirm >/dev/null

"$TMP/vpnctl" export-peers --api http://127.0.0.1:18788 --token-file "$TMP/admin/token"   --output "$TMP/gateway/export-active.json" --confirm > /dev/null
python3 - "$TMP/gateway/export-active.json" "$TMP/client/wg-public.key" <<'PYACTIVE'
import json,sys
records=json.load(open(sys.argv[1],encoding="utf-8"))
key=open(sys.argv[2],encoding="utf-8").read().strip()
assert len(records)==1 and records[0]["public_key"]==key and records[0]["address"]=="10.77.0.2/32"
PYACTIVE
"$TMP/vpnctl" config-gateway --dir "$TMP/gateway" --peers-file "$TMP/gateway/export-active.json"   --output "$TMP/gateway/gateway-from-registry.conf" --listen-port 51820 --confirm >/dev/null
grep -q 'AllowedIPs = 10.77.0.2/32' "$TMP/gateway/gateway-from-registry.conf"
"$TMP/vpnctl" revoke --api http://127.0.0.1:18788 --id "$ID" --token-file "$TMP/admin/token" --confirm >/dev/null
"$TMP/vpnctl" export-peers --api http://127.0.0.1:18788 --token-file "$TMP/admin/token"   --output "$TMP/gateway/export-revoked.json" --confirm > /dev/null
python3 - "$TMP/gateway/export-revoked.json" <<'PYREVOKE'
import json,sys
assert json.load(open(sys.argv[1],encoding="utf-8"))==[], "Revoked identity was re-exported"
PYREVOKE
"$TMP/vpnctl" config-gateway --dir "$TMP/gateway" --peers-file "$TMP/gateway/export-revoked.json"   --output "$TMP/gateway/gateway-after-revoke.conf" --listen-port 51820 --confirm >/dev/null
if grep -q '^\[Peer\]' "$TMP/gateway/gateway-after-revoke.conf"; then
  echo "Revoked peer still appears in rendered gateway config" >&2; exit 1
fi
kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""
"$TMP/vpnd" --listen 127.0.0.1:18788 --state-dir "$TMP/state" \
  --token-file "$TMP/admin/token" >"$TMP/server-restart.log" 2>&1 &
PID="$!"
for _ in {1..30}; do
  if curl -sSf --max-time 1 http://127.0.0.1:18788/healthz > /dev/null; then break; fi
  sleep 0.1
done
"$TMP/vpnctl" list --api http://127.0.0.1:18788 --token-file "$TMP/admin/token" >"$TMP/peers.json"
python3 - "$TMP/peers.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8"))["peers"]
assert len(p)==1 and p[0]["name"]=="isolated-test" and p[0]["revoked_at"]
print("PASS: localhost auth, React web, private split-tunnel configs, registry export, revoke exclusion and restart persistence")
PY

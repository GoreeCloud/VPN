#!/usr/bin/env bash
# Pure Linux agent plan test: never invokes network setup, sudo or NetBird.
set -euo pipefail
ROOT="$(pwd)"
TMP="$(mktemp -d /tmp/goreecloud-vpn-plan.XXXXXX)"
chmod 700 "$TMP"
cleanup(){ case "$TMP" in /tmp/goreecloud-vpn-plan.*) rm -rf -- "$TMP" ;; esac; }
trap cleanup EXIT
go build -o "$TMP/vpnctl" "$ROOT/cmd/vpnctl"
go build -o "$TMP/vpnagent" "$ROOT/cmd/vpnagent"
"$TMP/vpnctl" keygen --dir "$TMP/client" > /dev/null
"$TMP/vpnctl" keygen --dir "$TMP/gateway" > /dev/null
"$TMP/vpnagent" --action plan --private-key-file "$TMP/client/wg-private.key" \
  --gateway-public-key-file "$TMP/gateway/wg-public.key" \
  --address "10.77.0.2/32" --endpoint "vpn.example.test:51820" > "$TMP/plan"
grep -q 'DRY RUN ONLY' "$TMP/plan"
grep -q 'ip link add dev gcvpn0 type wireguard' "$TMP/plan"
grep -q 'wg set gcvpn0 private-key' "$TMP/plan"
grep -q 'ip -4 route add 10.77.0.0/24 dev gcvpn0' "$TMP/plan"
if grep -q -e '0.0.0.0/0' -e '^sudo ' -e 'netbird' "$TMP/plan"; then
  echo "Unsafe command or default route in plan" >&2
  exit 1
fi
if grep -qF "$(tr -d '\n' < "$TMP/client/wg-private.key")" "$TMP/plan"; then
  echo "Private key leaked into plan" >&2
  exit 1
fi
echo "PASS: Linux agent dry plan, fixed split route and secret-safe output"

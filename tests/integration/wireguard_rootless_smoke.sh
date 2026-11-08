#!/usr/bin/env bash
# Explicit manual integration test. No host VPN, DNS, routes or firewall changes.
# This script enters a fresh rootless user/network namespace BEFORE mutations.
set -euo pipefail
if [[ "${1:-}" != "--run" || $# -gt 2 ||
      ( $# -eq 2 && "${2:-}" != "--policy-preview" ) ]]; then
  echo "Usage: WG_BIN=/absolute/path/to/verified/wg bash $0 --run [--policy-preview]" >&2
  exit 2
fi
if [[ -z "${WG_BIN:-}" ]]; then
  WG_BIN=$(command -v wg || true)
fi
if [[ -z "$WG_BIN" || "$WG_BIN" != /* || ! -x "$WG_BIN" ]]; then
  echo "WireGuard tool unavailable; set WG_BIN to a verified absolute executable path" >&2
  exit 3
fi
if [[ "${GOREECLOUD_ISOLATED_LAB_CHILD:-0}" != "1" ]]; then
  if [[ $(id -u) -eq 0 ]]; then
    echo "Refusing to run as host root; use an authorized nonroot development environment" >&2
    exit 4
  fi
  for program in unshare nsenter ip nft ping timeout mount umount stat; do
    command -v "$program" >/dev/null || { echo "Missing required tool: $program" >&2; exit 3; }
  done
  parent_netns=$(readlink /proc/self/ns/net)
  parent_mountns=$(readlink /proc/self/ns/mnt)
  exec timeout 65 env GOREECLOUD_ISOLATED_LAB_CHILD=1 WG_BIN="$WG_BIN" \
    GOREECLOUD_PARENT_NETNS="$parent_netns" GOREECLOUD_PARENT_MOUNTNS="$parent_mountns" \
    unshare -Urnm bash "$0" "$@"
fi
WG="$WG_BIN"
self_ns=$(readlink /proc/self/ns/net)
self_mountns=$(readlink /proc/self/ns/mnt)
if [[ -z "${GOREECLOUD_PARENT_NETNS:-}" || "$self_ns" == "$GOREECLOUD_PARENT_NETNS" ||
      -z "${GOREECLOUD_PARENT_MOUNTNS:-}" || "$self_mountns" == "$GOREECLOUD_PARENT_MOUNTNS" ]]; then
  echo 'ERROR: fresh isolated network and mount namespaces are mandatory' >&2
  exit 4
fi
uid_map=$(awk 'NR==1 { print $1 ":" $2 ":" $3 }' /proc/self/uid_map)
# An explicit one-UID rootless mapping is required; never run as host root.
if [[ -z "$self_ns" || ! "$uid_map" =~ ^0:[1-9][0-9]*:1$ ]]; then
  echo 'ERROR: expected fresh rootless user and network namespaces' >&2
  exit 4
fi
umask 077
work=$(mktemp -d /tmp/goreecloud-vpn-isolated-keys.XXXXXX)
a='' b='' port_server=''
mounted=0
cleanup() {
  if [[ -n "$port_server" ]]; then kill "$port_server" 2>/dev/null || true; wait "$port_server" 2>/dev/null || true; fi
  if [[ -n "$a" ]]; then kill "$a" 2>/dev/null || true; wait "$a" 2>/dev/null || true; fi
  if [[ -n "$b" ]]; then kill "$b" 2>/dev/null || true; wait "$b" 2>/dev/null || true; fi
  if [[ "$mounted" == 1 ]]; then umount "$work" 2>/dev/null || true; fi
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' TERM INT
# Private mount namespace: test private keys never reach host-backed /tmp.
mount -t tmpfs -o size=4m,mode=0700 tmpfs "$work"
mounted=1
test "$(stat -f -c %T "$work")" = tmpfs

unshare -n sleep 70 &
a=$!
unshare -n sleep 70 &
b=$!
sleep 0.3
kill -0 "$a"
kill -0 "$b"

ip link add ga type veth peer name gb
ip link set ga netns "$a"
ip link set gb netns "$b"
nsenter -t "$a" -n ip link set lo up
nsenter -t "$b" -n ip link set lo up
nsenter -t "$a" -n ip addr add 172.29.50.1/30 dev ga
nsenter -t "$b" -n ip addr add 172.29.50.2/30 dev gb
nsenter -t "$a" -n ip link set ga up
nsenter -t "$b" -n ip link set gb up
nsenter -t "$a" -n ping -n -c 1 -W 2 172.29.50.2 >/dev/null
echo 'ISOLATED_UNDERLAY=PASS'

"$WG" genkey > "$work/a.priv"
"$WG" pubkey < "$work/a.priv" > "$work/a.pub"
"$WG" genkey > "$work/b.priv"
"$WG" pubkey < "$work/b.priv" > "$work/b.pub"

nsenter -t "$a" -n ip link add wgA type wireguard
nsenter -t "$b" -n ip link add wgB type wireguard
nsenter -t "$a" -n "$WG" set wgA listen-port 51820 private-key "$work/a.priv" peer "$(cat "$work/b.pub")" allowed-ips 10.77.0.11/32 endpoint 172.29.50.2:51821
nsenter -t "$b" -n "$WG" set wgB listen-port 51821 private-key "$work/b.priv" peer "$(cat "$work/a.pub")" allowed-ips 10.77.0.10/32 endpoint 172.29.50.1:51820
nsenter -t "$a" -n ip addr add 10.77.0.10/32 dev wgA
nsenter -t "$b" -n ip addr add 10.77.0.11/32 dev wgB
nsenter -t "$a" -n ip link set wgA up
nsenter -t "$b" -n ip link set wgB up
nsenter -t "$a" -n ip route add 10.77.0.11/32 dev wgA
nsenter -t "$b" -n ip route add 10.77.0.10/32 dev wgB

nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 2 -W 3 10.77.0.11 >/dev/null
handshake=$(nsenter -t "$a" -n "$WG" show wgA latest-handshakes | awk '{print $2}')
test "$handshake" -gt 0
echo 'KERNEL_WIREGUARD_ENCRYPTED_PING=PASS'
echo 'KERNEL_WIREGUARD_HANDSHAKE=PASS'

if [[ "${2:-}" == "--policy-preview" ]]; then
  # The preview compiler is *pure*; only this disposable namespace test applies it.
  root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
  PYTHONPATH="$root/src" python3 "$root/tests/integration/generate_nft_fixtures.py" "$work"
  nsenter -t "$b" -n nft -c -f "$work/deny.nft"
  nsenter -t "$b" -n nft -c -f "$work/allow.nft"
  nsenter -t "$b" -n nft -f "$work/deny.nft"
  if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
    echo 'ERROR: generated default-deny policy failed' >&2
    exit 5
  fi
  echo 'GENERATED_NFT_POLICY_DEFAULT_DENY=PASS'
  # Negative transaction: a malformed update must NOT remove the active deny.
  cat "$work/allow.replace.nft" > "$work/broken.replace.nft"
  printf '%s\n' 'nft_intentionally_invalid_command' >> "$work/broken.replace.nft"
  if nsenter -t "$b" -n nft -f "$work/broken.replace.nft" >/dev/null 2>&1; then
    echo 'ERROR: invalid nft batch unexpectedly accepted' >&2
    exit 8
  fi
  if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
    echo 'ERROR: rejected batch removed the active deny rule' >&2
    exit 8
  fi
  echo 'NFT_REJECTED_BATCH_PRESERVED_DENY=PASS'
  # nft -f commits a valid command batch as one kernel transaction.
  # This is still a manual, rootless namespace test; no agent is built.
  nsenter -t "$b" -n nft -c -f "$work/allow.replace.nft"
  nsenter -t "$b" -n nft -f "$work/allow.replace.nft"
  nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null
  echo 'GENERATED_NFT_POLICY_ICMP_ALLOW=PASS'
  # The following tests use a real socket listener in the RECEIVING lab namespace.
  # This is still a manual transaction, NOT a trusted production agent.
  nsenter -t "$b" -n nft -c -f "$work/ports.replace.nft"
  nsenter -t "$b" -n nft -f "$work/ports.replace.nft"
  nsenter -t "$b" -n python3 "$root/tests/integration/port_probe.py" serve --ready "$work/ports.ready" &
  port_server=$!
  for iteration in {1..40}; do
    if [[ -s "$work/ports.ready" ]]; then break; fi
    kill -0 "$port_server" 2>/dev/null || { echo 'port probe server quit early' >&2; exit 7; }
    sleep 0.1
  done
  test -s "$work/ports.ready"
  nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check tcp 8443
  echo 'GENERATED_NFT_ALLOWED_TCP_PORT=PASS'
  if nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check tcp 8444; then
    echo 'ERROR: unexpected access to denied TCP port 8444' >&2
    exit 7
  fi
  echo 'GENERATED_NFT_DENIED_TCP_PORT=PASS'
  nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check udp 5353
  echo 'GENERATED_NFT_ALLOWED_UDP_PORT=PASS'
  if nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check udp 5354; then
    echo 'ERROR: unexpected access to denied UDP port 5354' >&2
    exit 7
  fi
  echo 'GENERATED_NFT_DENIED_UDP_PORT=PASS'
  kill "$port_server" 2>/dev/null || true
  wait "$port_server" 2>/dev/null || true
  port_server=''
else
nsenter -t "$b" -n nft add table inet gcfilter
nsenter -t "$b" -n nft 'add chain inet gcfilter input { type filter hook input priority 0; policy accept; }'
nsenter -t "$b" -n nft add rule inet gcfilter input iifname wgB ip saddr 10.77.0.10 ip daddr 10.77.0.11 icmp type echo-request drop
if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
  echo 'ERROR: expected policy-denied ping to fail' >&2
  exit 5
fi
echo 'ISOLATED_NFT_KERNEL_DROP=PASS'
nsenter -t "$b" -n nft delete table inet gcfilter

nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null
echo 'KERNEL_WIREGUARD_POST_RULE_RESTORE=PASS'
fi

nsenter -t "$b" -n "$WG" set wgB peer "$(cat "$work/a.pub")" remove
if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
  echo 'ERROR: expected revoked WireGuard peer traffic to fail' >&2
  exit 6
fi
echo 'ISOLATED_WIREGUARD_PEER_REVOKE=PASS'
echo 'ISOLATED_LAB_FINISHED_AND_CLEANUP_SCHEDULED=TRUE'

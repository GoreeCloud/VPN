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
a='' b='' port_server='' stream_server='' stream_client=''
mounted=0
cleanup() {
  if [[ -n "$stream_client" ]]; then kill "$stream_client" 2>/dev/null || true; wait "$stream_client" 2>/dev/null || true; fi
  if [[ -n "$stream_server" ]]; then kill "$stream_server" 2>/dev/null || true; wait "$stream_server" 2>/dev/null || true; fi
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

# Verify the receiving kernel peer has precisely one /32 source binding.
peer_allowed_ips=$(nsenter -t "$b" -n "$WG" show wgB allowed-ips | awk '{print $2}')
if [[ "$peer_allowed_ips" != '10.77.0.10/32' ]]; then
  echo 'ERROR: unexpected receiver peer allowed source IP prefix' >&2
  exit 9
fi
echo 'KERNEL_WIREGUARD_SOURCE_PREFIX_BOUND=PASS'
# A sender can configure a second local address, but its peer identity
# must not authorize that forged source address at the receiver.
nsenter -t "$a" -n ip addr add 10.77.0.12/32 dev wgA
if nsenter -t "$a" -n ping -n -I 10.77.0.12 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
  echo 'ERROR: forged overlay source IP reached the receiving peer' >&2
  exit 9
fi
nsenter -t "$a" -n ip addr del 10.77.0.12/32 dev wgA
echo 'KERNEL_WIREGUARD_SOURCE_SPOOF_DENIED=PASS'

if [[ "${2:-}" == "--policy-preview" ]]; then
  # The preview compiler is *pure*; only this disposable namespace test applies it.
  root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
  PYTHONPATH="$root/src" python3 "$root/tests/integration/generate_nft_fixtures.py" "$work"
  # Nonsecret readback ONLY. Never use wg show dump (which includes private keys).
  nsenter -t "$b" -n "$WG" show wgB allowed-ips > "$work/observed.allowedips"
  PYTHONPATH="$root/src" python3 "$root/tests/integration/check_allowedips_readback.py" "$work"
  # Secondary local destination: prove it is reachable over encrypted WG
  # before any filter, so later denial cannot be a missing route or listener.
  nsenter -t "$b" -n ip addr add 10.77.0.13/32 dev wgB
  nsenter -t "$a" -n "$WG" set wgA peer "$(cat "$work/b.pub")" allowed-ips 10.77.0.11/32,10.77.0.13/32
  nsenter -t "$a" -n ip route add 10.77.0.13/32 dev wgA
  nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.13 >/dev/null
  echo 'WG_SECONDARY_LOCAL_IP_BASELINE_REACHABLE=PASS'
  nsenter -t "$b" -n nft -c -f "$work/deny.nft"
  nsenter -t "$b" -n nft -c -f "$work/allow.nft"
  nsenter -t "$b" -n nft -f "$work/deny.nft"
  if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.11 >/dev/null 2>&1; then
    echo 'ERROR: generated default-deny policy failed' >&2
    exit 5
  fi
  echo 'GENERATED_NFT_POLICY_DEFAULT_DENY=PASS'
  if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.13 >/dev/null 2>&1; then
    echo 'ERROR: secondary local IP bypassed interface-wide INPUT deny' >&2
    exit 12
  fi
  echo 'WG_SECONDARY_LOCAL_IP_BYPASS_DENIED=PASS'
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
  if nsenter -t "$a" -n ping -n -I 10.77.0.10 -c 1 -W 2 10.77.0.13 >/dev/null 2>&1; then
    echo 'ERROR: authorized target address accidentally opened alternate local IP' >&2
    exit 12
  fi
  echo 'WG_SECONDARY_LOCAL_IP_STILL_DENIED_AFTER_TARGET_ALLOW=PASS'
  # Run reverse-direction check while the responder still permits ICMP replies.
  # The later TCP/UDP-only rule blocks ICMP replies and would be ambiguous.
  # Demonstrate reverse traffic is permitted by WireGuard adjacency alone,
  # then denied by the independent *receiver* INPUT policy preview.
  nsenter -t "$b" -n ping -n -I 10.77.0.11 -c 1 -W 2 10.77.0.10 >/dev/null
  nsenter -t "$a" -n nft -c -f "$work/reverse.deny.nft"
  nsenter -t "$a" -n nft -f "$work/reverse.deny.nft"
  if nsenter -t "$b" -n ping -n -I 10.77.0.11 -c 1 -W 2 10.77.0.10 >/dev/null 2>&1; then
    echo 'ERROR: an unauthorized reverse-direction ping succeeded' >&2
    exit 10
  fi
  echo 'GENERATED_NFT_REVERSE_DIRECTION_DENIED=PASS'
  # An INPUT-only stateless deny also impacts reply packets for outbound flows.
  # Do not represent this preview as stateful bidirectional network security.
  nsenter -t "$a" -n nft delete table inet goreecloud_vpn_preview
  nsenter -t "$b" -n ping -n -I 10.77.0.11 -c 1 -W 2 10.77.0.10 >/dev/null
  echo 'KERNEL_REVERSE_DIRECTION_RESTORED_AFTER_LAB_RULE_REMOVAL=PASS'
  # Adversarial lab: inject an UNAPPROVED kernel WireGuard peer into the
  # receiving namespace. The guarded helper must reject the extra public
  # key BEFORE submitting any nft transaction; existing rules remain intact.
  "$WG" genkey > "$work/unauthorized.priv"
  "$WG" pubkey < "$work/unauthorized.priv" > "$work/unauthorized.pub"
  nsenter -t "$b" -n "$WG" set wgB peer "$(cat "$work/unauthorized.pub")" allowed-ips 10.77.0.12/32
  nsenter -t "$b" -n nft -j list chain inet goreecloud_vpn_preview input > "$work/before-rejection.json"
  if nsenter -t "$b" -n env PYTHONPATH="$root/src" python3 \
      "$root/tests/integration/lab_policy_transaction.py" --run \
      --private-lab-directory "$work" --wg-binary "$WG" > "$work/denied-readback.log" 2>&1; then
    echo 'ERROR: unapproved WireGuard peer was accepted by the guarded helper' >&2
    exit 14
  fi
  if ! grep -q 'public WireGuard peer readback differs' "$work/denied-readback.log"; then
    echo 'ERROR: unauthorized peer was not rejected for binding mismatch' >&2
    exit 14
  fi
  nsenter -t "$b" -n nft -j list chain inet goreecloud_vpn_preview input > "$work/after-rejection.json"
  if ! cmp -s "$work/before-rejection.json" "$work/after-rejection.json"; then
    echo 'ERROR: rejected peer changed the active nft chain' >&2
    exit 14
  fi
  echo 'GUARDED_LAB_UNAPPROVED_PEER_REJECTED_WITHOUT_NFT_CHANGE=PASS'
  nsenter -t "$b" -n "$WG" set wgB peer "$(cat "$work/unauthorized.pub")" remove
  # Inject an UNEXPECTED accept rule ahead of the terminal drop. A loose
  # string-search of drop + TCP/UDP patterns would miss this extra rule.
  # The exact JSON AST validator must refuse to modify the tainted chain.
  nsenter -t "$b" -n nft insert rule inet goreecloud_vpn_preview input iifname wgB accept
  nsenter -t "$b" -n nft -j list chain inet goreecloud_vpn_preview input > "$work/tampered-before.json"
  if nsenter -t "$b" -n env PYTHONPATH="$root/src" python3 \
      "$root/tests/integration/lab_policy_transaction.py" --run \
      --private-lab-directory "$work" --wg-binary "$WG" > "$work/tampered-result.log" 2>&1; then
    echo 'ERROR: extra nftables accept rule was accepted' >&2
    exit 15
  fi
  if ! grep -q 'exact lab ownership check' "$work/tampered-result.log"; then
    echo 'ERROR: nftables extra-rule rejection was not confirmed' >&2
    exit 15
  fi
  nsenter -t "$b" -n nft -j list chain inet goreecloud_vpn_preview input > "$work/tampered-after.json"
  if ! cmp -s "$work/tampered-before.json" "$work/tampered-after.json"; then
    echo 'ERROR: rejected unknown nftables rule changed the chain' >&2
    exit 15
  fi
  echo 'GUARDED_LAB_EXTRA_NFT_ACCEPT_REJECTED_WITHOUT_CHAIN_CHANGE=PASS'
  # Restore the known-good lab-only chain, then run the positive case.
  nsenter -t "$b" -n nft -f "$work/allow.replace.nft"
  # The following tests use a real socket listener in the RECEIVING lab namespace.
  # A test-only, guarded local helper compiles from one approved snapshot,
  # reads PUBLIC kernel AllowedIPs, then applies a fixed, validated nft batch.
  # No host/production networking or trusted production agent is involved.
  nsenter -t "$b" -n env PYTHONPATH="$root/src" python3 \
    "$root/tests/integration/lab_policy_transaction.py" --run \
    --private-lab-directory "$work" --wg-binary "$WG"
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
  # Start a *real established* TCP flow through the allowed port, then
  # transactionally withdraw the rule before sending the second payload.
  nsenter -t "$b" -n python3 "$root/tests/integration/port_probe.py" serve-stream --ready "$work/stream-server.ready" &
  stream_server=$!
  for iteration in {1..40}; do
    if [[ -s "$work/stream-server.ready" ]]; then break; fi
    kill -0 "$stream_server" 2>/dev/null || { echo 'stream server quit early' >&2; exit 11; }
    sleep 0.1
  done
  test -s "$work/stream-server.ready"
  nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check-stream --ready "$work/stream-client.ready" --go "$work/stream.go" &
  stream_client=$!
  for iteration in {1..40}; do
    if [[ -s "$work/stream-client.ready" ]]; then break; fi
    kill -0 "$stream_client" 2>/dev/null || { echo 'established stream failed' >&2; exit 11; }
    sleep 0.1
  done
  test -s "$work/stream-client.ready"
  nsenter -t "$b" -n nft -c -f "$work/deny.replace.nft"
  nsenter -t "$b" -n nft -f "$work/deny.replace.nft"
  : > "$work/stream.go"
  wait "$stream_client"
  stream_client=''
  kill -0 "$stream_server"
  echo 'KERNEL_ESTABLISHED_TCP_BLOCKED_AFTER_POLICY_WITHDRAWAL=PASS'
  kill "$stream_server" 2>/dev/null || true
  wait "$stream_server" 2>/dev/null || true
  stream_server=''
  nsenter -t "$b" -n nft -f "$work/ports.replace.nft"
  nsenter -t "$b" -n python3 "$root/tests/integration/port_probe.py" serve --ready "$work/restored.ready" &
  port_server=$!
  for iteration in {1..40}; do
    if [[ -s "$work/restored.ready" ]]; then break; fi
    kill -0 "$port_server" 2>/dev/null || { echo 'restored listener quit early' >&2; exit 11; }
    sleep 0.1
  done
  test -s "$work/restored.ready"
  nsenter -t "$a" -n python3 "$root/tests/integration/port_probe.py" check tcp 8443
  echo 'KERNEL_FRESH_TCP_RESTORED_AFTER_LAB_POLICY_REALLOW=PASS'
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

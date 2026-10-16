#!/usr/bin/env bash
# Read-only inventory for a possible future NetBird -> GoreeCloud VPN cutover.
# Does not inspect secrets, alter services, or authorize a migration.
set -euo pipefail

usage() {
  echo "Usage: $0 [--help]"
  echo "Read-only NetBird availability check. This does NOT certify migration readiness."
}

if [[ "${1:-}" == "--help" && $# -eq 1 ]]; then
  usage
  exit 0
fi
if (( $# != 0 )); then
  usage >&2
  exit 64
fi

failures=0
probe() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'PASS  %s\n' "$label"
  else
    printf 'BLOCK %s\n' "$label"
    failures=$((failures + 1))
  fi
}

has_container() {
  [[ "$running_containers" == *$'\n'"$1"$'\n'* ]]
}

printf 'NetBird baseline inventory (read-only, no service changes)\n'
probe "NetBird client executable" command -v netbird
probe "NetBird client service active" systemctl is-active --quiet netbird

running_containers=$'\n'
if command -v docker >/dev/null 2>&1; then
  if names="$(docker ps --format '{{.Names}}' 2>/dev/null)"; then
    running_containers+="$names"$'\n'
  else
    printf 'BLOCK Docker container inventory unavailable\n'
    failures=$((failures + 1))
  fi
else
  printf 'BLOCK Docker executable missing\n'
  failures=$((failures + 1))
fi
probe "NetBird server container running" has_container netbird-server
probe "NetBird dashboard container running" has_container netbird-dashboard

printf '\nMigration release gates NOT established by this inventory:\n'
printf '  - independently accepted GoreeCloud client/server builds and VPN functionality\n'
printf '  - control-plane compatibility, auth, policy and key-management tests\n'
printf '  - DNS, firewall, IPv4/IPv6, routes, leaks, revocation and outage tests\n'
printf '  - out-of-band console access, verified backup and tested NetBird rollback\n'
printf '  - privacy, licensing, vulnerability and security signoff\n'
printf 'DECISION: NO-GO — do not stop, replace, or modify production NetBird.\n'

if (( failures > 0 )); then
  printf 'BASELINE STATUS: %s prerequisites missing\n' "$failures"
  exit 1
fi
printf 'BASELINE STATUS: observed NetBird services available; migration still NO-GO\n'

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
umask 077
if [[ ! -s client-setup.key ]]; then
  if [[ ! -t 0 ]]; then
    echo "Use a private, interactive VPS terminal to enroll a NetBird setup key." >&2
    exit 2
  fi
  printf 'NetBird VPS setup key (input hidden): ' >&2
  IFS= read -r -s input
  printf '\n' >&2
  if [[ -z "${input}" || "${#input}" -gt 4096 ]]; then
    echo "Invalid or empty setup key." >&2
    exit 3
  fi
  printf '%s' "${input}" > client-setup.key
  unset input
  chmod 600 client-setup.key
fi
[[ "$(stat -c %a client-setup.key)" == 600 ]] || {
  echo 'Key file must be mode 0600.' >&2
  exit 4
}
docker compose -f docker-compose.peer.yml config --quiet
docker compose -f docker-compose.peer.yml up -d --no-build
echo "Peer started; verify with: docker exec goreecloud-netbird-client netbird status"
echo "Revoke enrollment key after stable peer activation; first remove the bootstrap key mount from Compose."

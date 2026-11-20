# GoreeCloud VPN local operations

**Development host only. No production deployment or live routing without separate end-to-end acceptance.**

## Run management console locally

Generate DIFFERENT local secrets, each at least 32 characters:

    export GCVPN_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export GCVPN_WEB_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export GCVPN_DB="$HOME/.local/state/goreevpn/peers.sqlite3"

Terminal A:

    PYTHONPATH=backend python3 -m goreevpn serve

Terminal B:

    cd web && npm ci && npm run dev

Open http://127.0.0.1:3000 locally, authenticate using the *web* secret and enroll 44-character canonical base64 WireGuard **public** keys. The backend is localhost-only and must never be directly Internet exposed. The web preview has no public production TLS/identity.

## Generate server config OFFLINE

Create and privately store a server private key with trusted system wg genkey and umask 077. Enroll peers in the UI. Default subnet 10.77.0.0/24 assumes no overlap with the host LAN; confirm first.

    PYTHONPATH=backend python3 -m goreevpn render-server --db "$GCVPN_DB" --key-file /secure/server.key --output /secure/gcvpn-review.conf

The generated config includes the **server private key**. Keep mode 0600, review addresses and AllowedIPs, and ensure the operator configures forwarding, firewall, DNS and routing using security policy before any separately authorized apply. This command never changes active routing, DNS, interface or firewall. When revoking, re-render and *actually apply* a reviewed server config; otherwise revocation is not effective on the network.

## Linux app

Build with Qt 6.12 and CMake. Independently install and audit system wireguard-tools and polkit. Before the app can connect, an administrator must review and provision a root-owned, non-symlink 0600 file /etc/wireguard/gcvpn.conf. The app uses explicit polkit authentication to run the system wg-quick program for this fixed file. Beware that wg-quick supports root-executed PreUp/PostUp/PreDown/PostDown shell hooks: audit or remove these before provisioning. Always preserve independent recovery access.

## Android app

Requires Android OS VPN permission on user-initiated Connect. Import a locally obtained, independently trusted WireGuard config via the system picker. GoBackend handles encrypted tunnel lifecycle; the app does not upload the file. The config is held only for the running process and not persisted. Device runtime, Android always-on VPN, consent denial, process death and route/DNS leak behavior have not passed acceptance.

## Recovery

Keep SSH or local console outside the proposed VPN. Backup the SQLite inventory separately from encrypted VPN private keys, test restoration on a spare host and verify access after explicit configuration changes.

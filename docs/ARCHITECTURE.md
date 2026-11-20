# GoreeCloud VPN — architecture and maturity

## Current source components

- Local operator browser: Next.js/React UI using GoreeCloud UI Lagoon alpha tokens. The browser only sends its login secret to a same-origin session endpoint; subsequent requests use an HttpOnly cookie.
- The Next.js server-side API has the backend token and proxies only explicit peer inventory routes to numeric loopback.
- Python management server: loopback HTTP, strict bearer validation, JSON endpoints GET /healthz, authenticated GET /api/v1/readiness, GET/POST /api/v1/peers and DELETE /api/v1/peers/{id}. The SQLite store keeps peer public keys and unique overlay addresses but not private peer keys.
- Offline renderer: reads owner-only server private-key file, writes 0600 WireGuard server config atomically. No privileged interface commands execute.
- Linux: separate Qt Quick UI. An administrator independently provisions root-owned /etc/wireguard/gcvpn.conf. Explicit polkit + wg-quick controls the local system WireGuard interface.
- Android: Kotlin Compose native UI imports a config through the OS file picker. Android OS VPN permission is requested on Connect; official WireGuard GoBackend handles the tunnel.

**No cross-client management API, live mesh, relay, peer discovery, policy firewall or automatically distributed trust exists.** Web enrollment does not configure the Linux or Android clients.

## Planned production design (not implemented)

Use GoreeCloud Identity for OIDC, device trust and scoped authorization, with short-lived enrollment. Use GoreeShield for consent, minimization, retention and transparency; Wardveil for threat defense and actual packet-policy verification. GoreeCloud Mesh coordinates only explicitly authorized, independently revocable service contracts. GoreeCloud UI controls the visible design across apps.

A future coordination service will own peer discovery, NAT traversal/relay selection, ACL distribution, key rotation and versioned policy; real wireguard-tools and GoBackend will remain the encryption data plane. Enforce deny-by-default policy on all applicable peers or gateways, including actual packet-path negative tests and explicit convergence for revoked identities. Avoid mandatory public cloud and preserve an independent recovery channel.

## Acceptance vocabulary

Source authored != compiled. Compilation != physical-device tested. Registered public key != active tunnel. Revoked DB row != data-plane revocation. Healthz != real packet connectivity. Open PR != merged main. Merged code != production deployment. Each milestone needs its own evidence.

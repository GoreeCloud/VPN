# Threat model — development scope

| Risk | Initial mitigation | Required acceptance |
| --- | --- | --- |
| Public access to management | Numeric loopback binding and bearer auth | No public exposure without TLS, identity/RBAC, rate limits and reverse-proxy trust review |
| Cross-site misuse | Same-origin mutation checks and HttpOnly SameSite cookies | CSRF/session/Host/proxy negative tests, HTTPS-only cookies |
| Private key leakage | No peer private keys accepted by admin API; private 0600 rendered server config | Secure memory lifecycle, encrypted backups, device keystore and secret scanning |
| Unauthorized peers | Canonical public key validation, address uniqueness | Approved device identity, deny-by-default packet ACL, encrypted 2-device test |
| Revoked peer still routes | Inventory marks revoked | Apply updated server config and demonstrate actual dropped traffic |
| Host command injection | Linux client fixed path, QProcess argument list and root-owner checks | Audit installed wg-quick config, eliminate root hooks and privilege-boundary tests |
| DNS/IPv6 leak | No claims of protections | Real dual-stack DNS/route/kill-switch tests |
| Software supply-chain | Source dependencies pinned in manifests/lockfile | Pin all CI action commits, SBOM, license review, reproducible/signed releases |
| Privacy leak | No tracking analytics or request logging | GoreeShield consent/retention control and Wardveil security audit |
| Lockout on cutover | No automatic network changes | Offline backup, independently tested recovery, staged rollback |

Production gates: positive and negative packet-path tests, endpoint identity, ACL and revocation convergence, DNS/IPv6 tests, NAT/relay/failure fallback, multi-device native acceptance, secret management, dependency auditing, anti-abuse, outage/recovery testing and independent policy review. No Stable/Anchor or production readiness is implied.

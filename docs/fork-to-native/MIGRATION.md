# NetBird-to-GoreeCloud VPN: controlled migration readiness

**Status: NO-GO. This is a development and recovery plan, not permission to cut over.**
The GoreeCloud VPN repository currently contains a NetBird-derived engineering baseline;
GoreeCloud VPN client/server compatibility, security, and stable release have not been accepted.

## Existing production boundary

The VPS has an active `netbird.service`, `netbird-server` container, and
`netbird-dashboard` container as observed in a read-only check on 2026-10-16.
Keep all three running and preserve their current data, identity, and production
routes throughout development. The repository's build/test pipelines must not
restart or otherwise alter them.

## Read-only prerequisite inventory

Run `bash scripts/preflight-netbird-migration.sh` on the intended VPS.
It checks only the presence of the NetBird client executable, active client
service, and two named running containers using read-only commands. It does
**not** inspect secrets or networking state and always prints a NO-GO decision.
A passing inventory confirms only that the baseline was visible, not that a
replacement is safe.

## Promotion gates (all required independently)

1. Reproducibly build and verify GoreeCloud VPN client, management, signal,
   relay and combined components; document exact Git revision and signed
   artifact provenance.
2. Remove or deliberately reconfigure inherited hosted management, admin,
   telemetry, debug upload and update endpoints; validate default runtime
   traffic using isolated network capture. Complete privacy and license review.
3. Validate WireGuard peer enrollment, MFA/identity, authorization, revocation,
   key rotation, IPv4/IPv6 policies, routing, DNS, split/full tunnel and leak
   protection, suspend/resume and recovery under outage conditions.
4. Test with synthetic identities and isolated DNS, tunnel and firewall
   resources. **Never reuse the production NetBird control-plane database,
   private keys, ports, interface, routing table changes or management identity**
   in a development test.
5. Verify an independently accessible VPS out-of-band console, restorable
   backups of configuration/data, protected recovery credentials, NetBird
   restoration instructions, and a rehearsed rollback on an isolated system.
6. Complete source, dependency, AGPL, security and release reviews. Obtain the
   owner-authorized production promotion and monitor a reversible canary.

## Cutover and rollback decision

The migration procedure must identify current deployment topology, durable
state and compatible client/server versions, required firewall/port changes,
DNS and route handoff, traffic observation, and the rollback trigger before
any shutdown or redirect. Favor a **parallel, isolated canary** whose failures
cannot affect NetBird production. Do not shut down NetBird until a validated
candidate, recovery path, and explicit promotion authorization exist.

If any gate fails, retain NetBird as production and return the candidate to
development. Passing a preflight script or GitHub CI by itself never changes
this decision.

Tracking: [VPN release criteria](https://github.com/GoreeCloud/VPN/issues/2) and
[upstream endpoint/privacy audit](https://github.com/GoreeCloud/VPN/issues/5).

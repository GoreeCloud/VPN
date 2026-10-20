# Integral platform systems — assessment backlog

None of the following entries constitutes an implemented or validated GoreeCloud VPN integration. Each item requires contract discovery, design, implementation, and runtime evidence.

| System | Initial applicability | Required assessment and evidence | Status |
| --- | --- | --- | --- |
| GoreeCloud Manager | Applicable | VPN service/process controls, privileged operations, lifecycle and upgrades | Not implemented |
| Privacy Shield | Applicable | Endpoint minimization, opt-in telemetry, permission/privacy settings, traffic exposure analysis | Not implemented |
| Wardveil Security | Applicable | Security posture, identity/authorization monitoring and incident boundaries | Not implemented |
| Everkeep | Evaluate | Encrypted configuration backup, recovery, safe restore without exporting keys | Not implemented |
| GoreeCloud UI | Applicable | Platform-specific native client UI, settings, onboarding, states and accessibility | Not implemented |
| GoreeCloud Mesh | Applicable | WireGuard peer/mesh interoperability, topology/identity and policy ownership | Not implemented |
| GoreeCloud Identity | Applicable | Account federation, session lifecycle, MFA and enrollment | Not implemented |
| GoreeCloud Policy | Applicable | Network access policy, per-peer scopes, auditability and revocation | Not implemented |
| GoreeCloud Observability | Applicable | Privacy-minimized diagnostics, opt-in metrics, event retention and incident evidence | Not implemented |

Avoid replacing existing upstream integrations until contracts and automated rollback tests exist. Record integration conformance with exact revision and runtime evidence.


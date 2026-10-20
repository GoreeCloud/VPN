# GoreeCloud VPN desktop setup — safer initial management selection

**Development only; no production promotion.** New desktop welcome screens, profile-creation dialogs, and a settings view with no configured management URL now start in **Self-hosted** mode rather than silently proposing NetBird's hosted management service.

For the fresh welcome flow and new profile creation, the hosted/cloud switch is not displayed. The operator must enter a management URL (or the managed-device policy can supply one for profile creation). Empty or invalid entered URLs are rejected before the wizard or modal submits them. Existing explicitly configured NetBird-cloud profiles retain their original endpoint and editing behavior; the changes do not rewrite stored profiles, WireGuard keys, or SSH identities.

A small Node source-contract test checks these default and guard choices in CI. This is **not** a browser/runtime acceptance test, UI accessibility review, native packaging test, or independent client-control-plane verification. Existing Settings and edit-profile screens retain legacy hosted controls for existing profiles; the Go profile manager also still applies inherited cloud defaults to new API/CLI provisioned configurations. Those are separate release blockers under issue #30 and must be addressed before any migration.

No production NetBird VPS configuration or service should be modified to exercise these desktop source checks.

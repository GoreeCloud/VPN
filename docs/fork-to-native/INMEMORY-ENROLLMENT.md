# In-memory client enrollment: explicit management address

**Development only — not authorization for a NetBird production cutover.**

New in-memory GoreeCloud VPN identities may be provisioned only after a management URL has been explicitly provided by the caller or resolved from an MDM management policy. The `profilemanager.CreateInMemoryConfig` provisioning entrypoint now rejects missing and whitespace-only management URLs before generating WireGuard/SSH keys. Explicit management addresses, including deliberately chosen legacy endpoints, remain compatible.

The embedded client now loads the existing MDM policy before new in-memory provisioning, uses its managed management URL when set, and reapplies the same policy after construction. The iOS SDK first-time in-memory login likewise resolves an MDM-enforced management URL before identity generation. These changes leave existing disk-backed profile creation, storage, reading, identity preservation, and policy overlay paths unchanged.

Scoped regression cases cover missing/whitespace URLs; configured self-hosted URL; intentional legacy URL; malformed explicit URL; valid MDM override; no policy; and an empty MDM key. GitHub CI tests profilemanager and embedded packages under Go 1.27. iOS platform compilation and real MDM provisioning require independent device/build validation; this CI does not prove them.

**Open acceptance blockers:** new disk-backed API/CLI/Android/iOS default hosted enrollment and inherited admin URL under issue #30; remaining diagnostic upload paths under #5; native signing/updater under #32; tunnel, DNS, firewall, IPv4/IPv6, leakage, recovery and cutover under #2. Keep NetBird production services, routes, DNS, interface, keys and state untouched.

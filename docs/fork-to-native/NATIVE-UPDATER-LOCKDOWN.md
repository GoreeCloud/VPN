# Native automatic updater lockout — unapproved release channel

**Status: development only. The signed GoreeCloud updater release channel does not exist yet.**

The inherited Windows/macOS automatic installer can download NetBird packages and retrieve signature material from NetBird infrastructure. It also targets NetBird service names. None of this may execute as a GoreeCloud VPN update. The service-triggered `Installer.RunInstallation` and the direct updater-process `Installer.Setup` are now both denied before touching result files, temporary directories, downloads, child processes or NetBird services. No environment setting can bypass the lockout; restoring signed updates requires a separate audited GoreeCloud-owned implementation and tests.

The native Windows and macOS Go packages plus their tests can be cross-compiled on Linux. Native runtime side-effects tests check the lockout and absence of filesystem changes when run on their respective platforms. A Linux-runnable source-policy test verifies both entrypoints have the gate as their first action. Cross-compilation and source scans do not prove native execution, UI behavior or data/traffic safety.

**Still required before release:** GoreeCloud-owned signed manifests, trusted keys/rotation/revocation, installer product identities, explicit user consent, artifact verification, native installer tests, staged update/rollback, platform-specific service safety, and complete VPN/migration acceptance (#2, #32). The existing production NetBird VPS and OS routing are not part of this change.

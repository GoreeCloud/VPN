# Inherited NetBird cloud profile migration — opt-in only

**Development status: not a migration release.** Existing NetBird client configurations and private keys must not be modified without explicit operator intent.

In the inherited client, the CLI `up` flow calls `profilemanager.UpdateOldManagementURL`. For legacy NetBird cloud profiles, that helper could silently probe the hosted endpoint and rewrite the management URL after a successful probe. GoreeCloud VPN now skips that compatibility migration by default: it makes no hosted probe and does not rewrite the profile unless `GOREECLOUD_ENABLE_LEGACY_CLOUD_MIGRATION=true` is deliberately set.

When an operator explicitly opts in, the inherited migration behavior can still run for relevant old hosted NetBird URLs. **This setting is not required for GoreeCloud self-hosted connections**, and it is not proof that GoreeCloud onboarding is independent of NetBird cloud defaults. Explicit opt-in does not constitute a general safety review of legacy cloud services.

Regression tests validate both the old behavior with opt-in and no-call/no-file-change/no-key-loss behavior when unset or given non-affirmative values. The package-level suite is run in GitHub CI.

Still blocked before a production cutover: new-client defaults and MDM enrollment in issue #30, native signed update channels #32, upstream cloud and diagnostic paths #5, and end-to-end routing/ACL/DNS/privacy and rollback acceptance #2. Never replace the production NetBird service based solely on these tests.

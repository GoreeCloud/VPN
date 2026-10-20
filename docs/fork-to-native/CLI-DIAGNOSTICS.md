# CLI diagnostics: local-only default

**Development safeguard only — GoreeCloud VPN is not released.**

The inherited NetBird CLI `debug bundle` and `debug for` commands previously offered `upload.debug.netbird.io` as the upload-service URL default. GoreeCloud now defaults both `--upload-bundle-url` flags to empty. Local debug-bundle generation remains available without any remote destination. With `--upload-bundle` selected, both commands validate *before* contacting the daemon or changing its state: an explicit HTTPS service is required; insecure-transport flag, malformed, credential-bearing, fragment-bearing, and inherited NetBird/Wiretrustee hosts are refused.

Passing an explicit HTTPS URL is operator intent to upload; it does not establish ownership or consent for a third-party destination, and server-side authorization, redirect behavior, collection/anonymization and egress must still be reviewed independently. Android/iOS native support-bundle APIs and daemon privilege exceptions remain unresolved under privacy issue #5. Signed release channels and all network/runtime migration gates also remain open under #32 and #2.

Regression tests check local-only default, rejected inherited and insecure targets, explicit HTTPS acceptance, CLI default flag values, and early failure before daemon connection. No user data or running NetBird VPS service is changed by this source-level patch.

# Diagnostic bundle upload privilege guard

**Security baseline development; not a production rollout.** The inherited NetBird daemon treated `upload.debug.netbird.io` as a trusted default service that any unprivileged local caller could use for diagnostic bundle uploads. GoreeCloud does not grant that exception. All remote diagnostic upload destinations require privileged caller identity. Generating a local-only bundle is unaffected, and a privileged caller can still select a supported endpoint under the daemon's existing URL validation.

The existing daemon privilege tests now require elevation for the inherited NetBird default host, alternate paths, a DNS-root-dot spelling and arbitrary self-hosted HTTPS destinations. The tests also verify insecure uploads and invalid URI schemes remain appropriately gated. A pinned Go 1.27 CI job runs the `client/server` test and vet packages.

This removes an inherited trust exception but does **not** certify that mobile/CLI clients refuse hosted upload destinations, that the daemon follows redirects safely, or that a privileged caller has secured informed diagnostic data consent. Those require further work under issue #5; signed channels #32, native deployment and end-to-end VPN migration #2 remain NO-GO. No production NetBird VPS services or network state have been modified.

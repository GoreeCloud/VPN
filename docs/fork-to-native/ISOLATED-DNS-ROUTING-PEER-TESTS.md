# Isolated DNS, routing and peer regression tests

**Validation scope: development packages only, not VPS migration acceptance.**

The inherited DNS upstream resolver test previously queried public DNS servers (`8.8.8.8` and `8.8.4.4`) to validate success and failover, so the suite failed in a network-disabled test container. GoreeCloud now substitutes the package's existing deterministic upstream mock for those requests, covering synthetic A-record success, first-server failure, both upstreams unavailable and canceled parent context. No public resolver traffic is needed.

The `offline-dns-routing-peer-tests` GitHub Actions job runs the DNS, routing-manager and peer Go unit-test suites and static analysis under Go 1.27, alongside existing ACL and management checks.

**Local no-network verification:** Docker Go 1.27, `--network none --cap-drop ALL --security-opt no-new-privileges`, read-only source mount, offline module cache. Full suite results recorded in PR once available. Passing tests here does not verify the host DNS resolver, kernel WireGuard interface, IPv6 route installation, real client peers, cross-namespace traffic, netfilter, DNS leaks or NetBird-to-GoreeCloud production cutover. These require a separate isolated functional environment and demonstrated restore/rollback; migration remains NO-GO (#2).

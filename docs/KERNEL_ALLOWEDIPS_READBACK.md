# GoreeCloud VPN — read-only WireGuard AllowedIPs reconciliation

**Status:** early development, test-only. This component parses **public-key-only** text returned by the WireGuard command `wg show INTERFACE allowed-ips`. It does not invoke WireGuard, read a private key, attest a kernel or change any network interface or firewall.

## Pure functions

- `parse_allowedips_text(text, pool="10.77.0.0/24")` parses a bounded set of `public-key<TAB>IPv4/32` lines. It rejects malformed/noncanonical keys, prefixes outside the configured RFC1918 pool, non-/32 prefixes, duplicate peer keys, duplicate source prefixes, and unexpected extra fields or overlapping source intent.
- `compare_allowedips_to_intent(intent, text, expected_peer_ids=[...])` compares that parsed text with a **selected subset** of peer IDs from an independently created `build_key_address_binding_intent()` manifest. It reports missing, unexpected and prefix-mismatched **public keys**; an unknown peer ID is rejected. The caller must explicitly select which authorized peers should be installed on a particular local interface.

A successful `text_matches_selected_intent` result is **not** a device authentication proof, independently verified live kernel state, or valid production configuration. The result explicitly declares `readback_source_authenticated:false`, `active_kernel_state_attested:false`, `applied:false`, and `data_plane_enforced:false`. Neither the local manifest nor a text string is inherently authenticated.

## Disposable kernel test

The explicitly invoked rootless test in [ISOLATED_WIREGUARD_LAB](ISOLATED_WIREGUARD_LAB.md) generates disposable peer keys on private tmpfs, registers the corresponding **public** keys in a temporary management store, and prepares a read-only binding manifest. It obtains only the receiving interface's `wg show wgB allowed-ips` output from inside the dedicated disposable network namespace, then verifies that the actual peer public key and `10.77.0.10/32` source binding match the selected approved management record.

**Never use `wg show INTERFACE dump` or `wg show INTERFACE private-key` for this comparison:** those commands can expose the private key in their output. No raw public readback file or secret material should be committed, logged or sent to third-party services in production.

The test also checks one forged-source IP is rejected by kernel WireGuard cryptokey routing, but it does not prove that GoreeCloud has a trusted control plane, enrollment, atomic agent, or complete multi-peer packet policies.

## Release gates

A future least-privileged agent must securely obtain an authoritative signed policy and authenticated device identity, verify the actual intended WireGuard interface and peer state directly, reject unexpected peers/mismatched AllowedIPs, constrain all address scopes, and transactionally install matching packet-path ACLs. It must test revocation, conntrack/established connections, restart/outage and rollback with hostile clients. P0 issue [#22](https://github.com/GoreeCloud/VPN/issues/22) tracks these requirements.

This module is a pure testable input validator and **must not** be used as an authorization decision based solely on supplied text.

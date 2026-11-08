# GoreeCloud VPN implementation status

Status: early development, last verified November 7, 2026. The public repository originally contained only a placeholder README. This file documents the delivery boundary: no production deployment, no claim of working WireGuard tunnels, and no modification of the existing NetBird installation.

Development checkpoint: peer records require explicit administrator approval, revocation preserves a permanent key tombstone, pre-approval databases migrate to pending, and local lifecycle events are recorded. These are management-state controls only; no actual data-plane security is asserted.

See docs/THREAT_MODEL.md for specific identity, packet-policy, route, relay and release requirements. A read-only peer planning preview has been added, but does not configure WireGuard or enforce traffic.

Verified November 7 checkpoint: MIT licensing and SPDX metadata are merged (PR #16). Management HTTP now rejects unrecognized or duplicate Host headers, browser Origin headers and absolute-URI request targets (PR #17). Nonpublishing wheel builds and wheel license/metadata validation are merged (PR #18). GitHub PR CI passed Python 3.11/3.12/3.13. A clean development-laptop checkout passed 53 Python 3.12 tests; an isolated wheel install and CLI help smoke passed. These tests do **not** demonstrate actual encrypted tunnels, packet enforcement, secure remote device enrollment, live revocation or production readiness.

Draft PR #6 for X25519 device key-possession remains unmerged pending independent cryptographic security review. Its conflicts with main were reconciled on the draft branch; 65 local tests and the exact updated GitHub PR CI matrix on Python 3.11/3.12/3.13 passed. This does **not** authorize production enrollment or a secure data-plane deployment.

November 7 isolated kernel lab milestone: PR #19 added an observation-only Linux prerequisite checker. PR #20 added a *manual, opt-in* unprivileged user/network/mount namespace test that demonstrated a real kernel WireGuard handshake and encrypted ICMP, an nftables drop of a decrypted packet, restored traffic after rule deletion and peer-key removal blocking traffic. Key material was held on private tmpfs and cleanup verified; the test was repeated from the public branch. The branch passed 62 local Python tests and GitHub CI on Python 3.11/3.12/3.13. **The VPN product did not provision these peers or enforce these rules**; a reviewed privileged agent, actual policy translation, cryptographic enrollment and an authorized deployment remain unimplemented. See [ISOLATED_WIREGUARD_LAB](ISOLATED_WIREGUARD_LAB.md).

Current experimental candidate: an offline nftables IPv4 INPUT policy preview translates approved source/target group rules to inspectable accept/drop text. The separate rootless lab has manually validated the generated ICMP deny and allow behavior using actual ephemeral public keys. No privileged GoreeCloud network agent or atomic/stateful production ACL deployment exists. See [NFT_INGRESS_PREVIEW](NFT_INGRESS_PREVIEW.md).

Priority sequence: secure identity and enrollment; real WireGuard data-plane enforcement; routing and DNS; clients; observability; remote access; enterprise and AI modules. GoreeCloud Mesh owns inter-product orchestration, while GoreeCloud UI governs visual surfaces.

Management inspection additions: authenticated status (lifecycle, group and pool
counts), access explanations/batch simulation, static policy diagnostics,
filtered event pagination and a local `goreecloud-vpnctl` inspection CLI. See
[usage and limits](MANAGEMENT_INSPECTION.md). They are management-only and do not
change the security/production gates above. No database schema change is needed.

"""Check only nonsecret WireGuard allowed-ips output inside the disposable lab."""
from __future__ import annotations
import json
import ipaddress
from pathlib import Path
import sys
from goreecloud_vpn.agent_preflight import build_offline_ingress_preflight
from goreecloud_vpn.kernel_readback import compare_allowedips_to_intent


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: check_allowedips_readback.py PRIVATE_LAB_DIRECTORY")
    directory = Path(argv[1])
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("private lab directory is invalid")
    intent = json.loads((directory / "binding-intent.json").read_text(encoding="ascii"))
    source_id = (directory / "binding-source-id.txt").read_text(encoding="ascii")
    observed = (directory / "observed.allowedips").read_text(encoding="ascii")
    report = compare_allowedips_to_intent(
        intent, observed, expected_peer_ids=[source_id]
    )
    if not report["text_matches_selected_intent"]:
        raise RuntimeError("observed public kernel key/IP prefixes do not match the lab intent")
    print("KERNEL_PUBLIC_KEY_ALLOWEDIPS_READBACK_MATCHES_MANIFEST=PASS")

    # Recompile firewall + key intent from ONE frozen lab generation, then
    # verify source identity and policy rules against actual PUBLIC wg text.
    state = json.loads((directory / "lab-state.json").read_text(encoding="ascii"))

    class LabSnapshot:
        def __init__(self, payload):
            self.network = ipaddress.ip_network(payload["pool"], strict=True)
            self._peers, self._policies = payload["peers"], payload["policies"]
            self.calls = 0

        def snapshot(self):
            self.calls += 1
            if self.calls != 1:
                raise RuntimeError("preflight must never mix generations")
            return self._peers, self._policies

    lab = LabSnapshot(state)
    preflight = build_offline_ingress_preflight(
        lab, state["target_peer_id"], observed, interface="wgB"
    )
    if lab.calls != 1 or preflight["source_peer_ids"] != [source_id]:
        raise RuntimeError("incorrect source selection or mixed snapshot")
    if preflight["firewall_preview"]["nftables_text"] != (
        directory / "ports.nft"
    ).read_text(encoding="ascii"):
        raise RuntimeError("one-snapshot ingress policy does not match lab fixture")
    if preflight["agent_invoked"] or preflight["applied"]:
        raise RuntimeError("offline-only preflight unexpectedly claims to apply policy")
    print("SINGLE_SNAPSHOT_POLICY_KEY_READBACK_PREFLIGHT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

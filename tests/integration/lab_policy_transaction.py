"""Manual, rootless-only policy transaction in a disposable WireGuard lab.

NOT a production GoreeCloud VPN agent. Deliberately installed only under tests.
Never uses a shell, accepts a raw nft program, or touches outside namespaces.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

from goreecloud_vpn.agent_preflight import build_offline_ingress_preflight
from goreecloud_vpn.firewall_preview import build_nft_ingress_preview
from port_probe import _assert_isolated_lab
from nft_exact_readback import check_exact_lab_chain

NFT = Path("/usr/sbin/nft")
IFACE = "wgB"
TABLE = "goreecloud_vpn_preview"


def _exec(command: list[str], *, source: str | None = None) -> str:
    result = subprocess.run(
        command, input=source, text=True, capture_output=True,
        timeout=6, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    )
    if result.returncode != 0:
        raise RuntimeError("isolated kernel command failed")
    return result.stdout


class _OneSnapshot:
    def __init__(self, payload):
        self.network = ipaddress.ip_network(payload["pool"], strict=True)
        self._peers, self._policies = payload["peers"], payload["policies"]
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        if self.calls != 1:
            raise RuntimeError("preflight attempted to mix policy snapshots")
        return self._peers, self._policies


def apply_lab_only(directory: Path, wg_binary: Path, *, test_force_postcheck_failure=False) -> None:
    _assert_isolated_lab()  # Before any subprocess or network activity
    if (directory.is_symlink() or not directory.is_dir()
            or directory.parent != Path("/tmp")
            or not directory.name.startswith("goreecloud-vpn-isolated-keys.")
            or directory.stat().st_uid != os.geteuid()
            or directory.stat().st_mode & 0o077):
        raise RuntimeError("lab fixture is not in its own owner-only temporary directory")
    # The outer rootless shell created and verified this private tmpfs.
    # Check it again here: the helper must not rely solely on env markers.
    mount_lines = Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
    if not any(
        " - tmpfs " in line and line.split(" ")[4] == str(directory)
        for line in mount_lines if len(line.split(" ")) > 5
    ):
        raise RuntimeError("expected private tmpfs mounted at exact fixture path")
    if (not wg_binary.is_absolute() or not wg_binary.is_file()
            or not os.access(wg_binary, os.X_OK)):
        raise RuntimeError("verified absolute WireGuard executable required")
    if not NFT.is_file() or not os.access(NFT, os.X_OK):
        raise RuntimeError("nft executable not found")

    # Only public WireGuard peer source-prefix data is requested. No dump,
    # private key, or arbitrary interface selector is accepted by this tool.
    observed = _exec([str(wg_binary), "show", IFACE, "allowed-ips"])
    state_path = directory / "lab-state.json"
    if state_path.is_symlink():
        raise RuntimeError("lab snapshot cannot be a symlink")
    state = json.loads(state_path.read_text(encoding="ascii"))
    snapshot = _OneSnapshot(state)
    preflight = build_offline_ingress_preflight(
        snapshot, state["target_peer_id"], observed, interface=IFACE
    )
    if (snapshot.calls != 1 or preflight["agent_invoked"]
            or preflight["applied"] or preflight["data_plane_enforced"]
            or preflight["kernel_readback_authenticated"]
            or preflight["allowed_source_count"] != 1):
        raise RuntimeError("unexpected offline preflight result")
    source_id = (directory / "binding-source-id.txt").read_text(encoding="ascii")
    if preflight["source_peer_ids"] != [source_id]:
        raise RuntimeError("lab source does not match approved policy")

    preview = preflight["firewall_preview"]
    expected = (directory / "ports.replace.nft").read_text(encoding="ascii")
    transaction = preview["nftables_replace_transaction_text"]
    if transaction != expected or preview["allow_rule_count"] != 2:
        raise RuntimeError("generated kernel update does not match fixture intent")
    # Verify the fixed, dedicated chain already has an active interface drop.
    matches = [b for b in preflight["binding_manifest"]["bindings"]
               if b["peer_id"] == source_id]
    if len(matches) != 1:
        raise RuntimeError("unapproved or duplicated source peer binding")
    source_ip = matches[0]["allowed_ips"][0].removesuffix("/32")
    target_ip = preview["target_ipv4"]
    # Exact AST validation, not string-search. Before must be exactly the
    # prior ICMP allow + final interface drop. Unknown/extra rules are fatal.
    before = _exec([str(NFT), "-j", "list", "chain", "inet", TABLE, "input"])
    check_exact_lab_chain(before, source=source_ip, target=target_ip, stage="pre")
    # Prepare and validate a separate compiler-generated default-deny fallback
    # BEFORE changing the disposable chain. Never execute caller-supplied nft.
    deny_state = dict(state)
    deny_state["policies"] = []
    deny_preview = build_nft_ingress_preview(
        _OneSnapshot(deny_state), state["target_peer_id"], interface=IFACE
    )
    if deny_preview["allow_rule_count"] != 0:
        raise RuntimeError("default-deny fallback unexpectedly includes allow rules")
    deny_transaction = deny_preview["nftables_replace_transaction_text"]
    _exec([str(NFT), "-c", "-f", "-"], source=deny_transaction)
    _exec([str(NFT), "-c", "-f", "-"], source=transaction)
    try:
        _exec([str(NFT), "-f", "-"], source=transaction)
        after = _exec([str(NFT), "-j", "list", "chain", "inet", TABLE, "input"])
        if test_force_postcheck_failure:
            raise RuntimeError("deliberately injected lab post-apply readback failure")
        check_exact_lab_chain(after, source=source_ip, target=target_ip, stage="post")
    except (RuntimeError, OSError, subprocess.SubprocessError) as failure:
        # Fail closed in THIS DISPOSABLE NAMESPACE only. The caller still
        # receives an error even if the emergency deny is verified.
        try:
            _exec([str(NFT), "-f", "-"], source=deny_transaction)
            fallback = _exec([str(NFT), "-j", "list", "chain", "inet", TABLE, "input"])
            check_exact_lab_chain(fallback, source=source_ip, target=target_ip, stage="deny")
        except (RuntimeError, OSError, subprocess.SubprocessError) as recovery_error:
            raise RuntimeError("emergency lab deny could not be verified") from recovery_error
        raise RuntimeError("post-apply lab failure: emergency default deny installed and verified") from failure
    print("GUARDED_ROOTLESS_COMPILED_POLICY_TRANSACTION=PASS")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in rootless-only GoreeCloud VPN lab transaction")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--private-lab-directory", type=Path)
    parser.add_argument("--wg-binary", type=Path)
    parser.add_argument("--test-force-postcheck-failure", action="store_true",
                        help="rootless lab fault injection; never use outside tests")
    args = parser.parse_args(argv)
    if not args.run or not args.private_lab_directory or not args.wg_binary:
        parser.error("requires --run, --private-lab-directory and --wg-binary")
    try:
        apply_lab_only(args.private_lab_directory, args.wg_binary,
                       test_force_postcheck_failure=args.test_force_postcheck_failure)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"LAB REFUSED: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

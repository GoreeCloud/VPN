"""Read-only Linux lab prerequisite inspection for future WireGuard tests.

This module NEVER runs wg, ip, nft, sudo, unshare, commands, or socket operations.
Observations are informational and cannot prove a VPN is operating securely.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import re
import shutil

SCHEMA = "goreecloud.vpn.lab-prerequisites.v1"
CAP_NET_ADMIN = 12
STATUS_PATTERN = re.compile(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", re.MULTILINE)


def _effective_net_admin(proc_status: str | None) -> bool | None:
    """Return None on missing or ambiguous Linux process capability data."""
    if not isinstance(proc_status, str):
        return None
    matches = STATUS_PATTERN.findall(proc_status)
    if len(matches) != 1:
        return None
    try:
        return bool(int(matches[0], 16) & (1 << CAP_NET_ADMIN))
    except ValueError:
        return None


def inspect_lab(
    *,
    platform_name: str | None = None,
    which=None,
    proc_status: str | None = None,
    module_visible: bool | None = None,
    namespace_visible: bool | None = None,
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
) -> dict:
    """Inspect prerequisites without mutating or enumerating existing networks.

    Injectable values support safe and deterministic regression tests. These
    observations do NOT establish actual CAP_NET_ADMIN use, tunnel support,
    firewall effectiveness, namespace isolation, or deployment authorization.
    """
    os_name = platform_name if platform_name is not None else platform.system()
    find_command = which if which is not None else shutil.which
    checks = []

    def check(name: str, status: str, message: str) -> None:
        checks.append({"id": name, "status": status, "detail": message})

    check("linux", "pass" if os_name == "Linux" else "blocked",
          "Linux is required for this isolated network-namespace lab")

    for program in ("wg", "ip", "nft", "unshare"):
        found = bool(find_command(program))
        check(
            f"tool_{program}",
            "pass" if found else "blocked",
            f"{program} executable " + ("found" if found else "not found"),
        )

    if proc_status is None:
        try:
            proc_status = (proc_root / "self/status").read_text(encoding="ascii")
        except (OSError, UnicodeError):
            proc_status = ""
    net_admin = _effective_net_admin(proc_status)
    check(
        "cap_net_admin",
        "unverified" if net_admin is None else ("pass" if net_admin else "blocked"),
        "Effective CAP_NET_ADMIN " +
        ("cannot be determined" if net_admin is None else
         ("is present" if net_admin else "is absent")),
    )

    if namespace_visible is None:
        namespace_visible = (proc_root / "self/ns/net").exists()
    check("network_namespace",
          "pass" if namespace_visible else "unverified",
          "Network namespace process entry " +
          ("exists; isolation has not been tested" if namespace_visible
           else "is not observable"))

    if module_visible is None:
        module_visible = (sys_root / "module/wireguard").exists()
        if not module_visible:
            try:
                with (proc_root / "modules").open("r", encoding="ascii") as source:
                    module_visible = any(line.startswith("wireguard ") for line in source)
            except (OSError, UnicodeError):
                module_visible = False
    check(
        "kernel_wireguard",
        "pass" if module_visible else "unverified",
        "WireGuard module " +
        ("is visible; functionality not tested" if module_visible
         else "not visible; built-in support remains possible"),
    )

    present = all(entry["status"] == "pass" for entry in checks)
    return {
        "schema": SCHEMA,
        "platform": os_name,
        "checks": checks,
        "observed_prerequisites_present": present,
        "real_wireguard_tunnel_verified": False,
        "packet_policy_enforcement_verified": False,
        "network_mutations_performed": False,
        "warning": (
            "Observation only. Never run privileged lab or production network "
            "changes without a disposable isolation plan, cleanup and explicit checks."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect Linux WireGuard lab prerequisites (read-only)"
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable report")
    parser.add_argument("--strict", action="store_true",
                        help="Return exit 2 unless all observable prerequisites pass")
    args = parser.parse_args(argv)
    report = inspect_lab()
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print("GoreeCloud VPN — read-only WireGuard lab prerequisite inspection")
        for item in report["checks"]:
            print(f"  {item['id']}: {item['status']} — {item['detail']}")
        print("Actual tunnel and packet enforcement: NOT TESTED")
        print("Host network configuration: UNCHANGED")
    return 2 if args.strict and not report["observed_prerequisites_present"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

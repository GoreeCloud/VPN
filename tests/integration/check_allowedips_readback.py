"""Check only nonsecret WireGuard allowed-ips output inside the disposable lab."""
from __future__ import annotations
import json
from pathlib import Path
import sys
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

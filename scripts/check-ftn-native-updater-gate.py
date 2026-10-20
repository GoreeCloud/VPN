#!/usr/bin/env python3
"""Source-level fail-closed gate check; not a native-platform runtime test."""

from pathlib import Path
import re

base = Path(__file__).resolve().parents[1] / "client/internal/updater/installer"
candidates = {
    "installer_common.go": "RunInstallation",
    "installer_run_windows.go": "Setup",
    "installer_run_darwin.go": "Setup",
}

for filename, method in candidates.items():
    source = (base / filename).read_text()
    pattern = (
        r"func \(u \*Installer\) " + method
        + r"\([^)]*\) \([^)]*\) \{\s*"
        + r"(?://[^\n]*\n\s*)*"
        + r"if err := requireApprovedNativeReleaseChannel\(\); err != nil \{\s*"
        + r"return err\s*\}"
    )
    if not re.search(pattern, source):
        raise SystemExit(f"FAIL: {filename}: {method} lacks first-action native release gate")
    print(f"PASS: {filename} {method} fail-closed before side effects")

common = (base / "installer_common.go").read_text()
if not re.search(
    r"func requireApprovedNativeReleaseChannel\(\) error \{\s*"
    r"return fmt.Errorf\(\"GoreeCloud automatic installation disabled:"
    r" signed native update channel is not approved\"\)\s*\}",
    common,
):
    raise SystemExit("FAIL: no unconditional, non-overridable native release denial")
print("PASS: no operator flag or environment override can enable legacy installer")

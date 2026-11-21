#!/usr/bin/env python3
"""Offline, provisional SPDX 2.3 dependency inventory for GoreeCloud VPN.

This is NOT a complete production SBOM or a license compliance conclusion:
Android transitive Gradle resolutions and native Qt/WireGuard shared libraries
must be obtained from exact release artifacts and reviewed independently.
No network, environment secrets, GitHub API, or package installation is used.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0"


def item(kind: str, name: str, version: str, declared: str = "NOASSERTION", detail: str = "") -> dict:
    if not kind or not name or not version:
        raise ValueError("dependency inventory must identify its source, name and version")
    if not isinstance(declared, str) or not declared:
        declared = "NOASSERTION"
    identity = f"{kind}|{name}|{version}"
    identifier = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return {
        "SPDXID": f"SPDXRef-Package-{identifier}",
        "name": name,
        "versionInfo": version,
        "filesAnalyzed": False,
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": declared,
        "copyrightText": "NOASSERTION",
        "comment": f"Source category: {kind}. {detail}",
    }


def npm_packages(root: Path) -> list[dict]:
    path = root / "web/package-lock.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("lockfileVersion") != 3 or not isinstance(data.get("packages"), dict):
        raise ValueError("unexpected npm lockfile schema")
    entries = []
    for location, info in data["packages"].items():
        if not location:
            continue
        if not isinstance(info, dict) or info.get("link"):
            continue
        if "node_modules/" not in location:
            raise ValueError("unexpected npm package location")
        name = location.split("node_modules/")[-1]
        version = info.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"npm package {name} missing pinned version")
        license_text = info.get("license")
        declared = license_text if isinstance(license_text, str) and license_text else "NOASSERTION"
        scope = "development dependency" if info.get("dev") else "runtime or shared dependency"
        entries.append(item("npm lockfile", name, version, declared, scope))
    return entries


def android_packages(root: Path) -> list[dict]:
    app = (root / "android/app/build.gradle.kts").read_text(encoding="utf-8")
    build = (root / "android/build.gradle.kts").read_text(encoding="utf-8")
    entries = []
    pattern = r'^\s*(implementation|testImplementation)\s*\(\s*(?:platform\()?\s*"([^"]+)"'
    for match in re.finditer(pattern, app, re.MULTILINE):
        scope, coordinate = match.groups()
        bits = coordinate.split(":")
        if len(bits) not in (2, 3) or not all(bits):
            raise ValueError("unexpected Android dependency coordinate")
        name = ":".join(bits[:2])
        version = bits[2] if len(bits) == 3 else "NOASSERTION"
        entries.append(item("Gradle declaration", name, version, detail=f"{scope}; "
            "transitive resolved dependency information and licenses pending review"))
    pattern = r'\bid\("([^"]+)"\)\s+version\s+"([^"]+)"\s+apply\s+false'
    for match in re.finditer(pattern, build):
        entries.append(item("Gradle build plugin", match.group(1), match.group(2),
                            detail="build plugin; license and transitive dependencies not asserted"))
    if not entries:
        raise ValueError("no Android dependencies found")
    return entries


def go_packages(root: Path) -> list[dict]:
    gomod = (root / "go.mod").read_text(encoding="utf-8")
    if not re.search(r"(?m)^module github.com/GoreeCloud/VPN$", gomod):
        raise ValueError("unexpected first-party Go module")
    # This development module currently has no third-party requires. Reject
    # silently changing that assumption; a future parser must inspect go.sum.
    requires = re.findall(r"(?m)^\s*require\b", gomod)
    if requires:
        raise ValueError("Go requirements added: update the dependency inventory parser")
    return []


def qt_packages(root: Path) -> list[dict]:
    cmake = (root / "desktop/linux/CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"find_package\(Qt6\s+([0-9.]+)\s+REQUIRED\s+COMPONENTS\s+Quick\)", cmake)
    if not match:
        raise ValueError("Qt Quick source version could not be resolved")
    return [item("Qt development requirement", "Qt6 Quick", match.group(1),
                 detail="system Qt build dependency; license and platform binaries pending artifact review")]


def make_spdx(root: Path, created: str | None = None) -> dict:
    packages = [item("first-party source", "GoreeCloud VPN", "NOASSERTION", "Apache-2.0",
                     "license applies to the original source only")]
    packages += npm_packages(root)
    packages += android_packages(root)
    packages += go_packages(root)
    packages += qt_packages(root)
    keys = [(v["SPDXID"], v["name"]) for v in packages]
    if len({k for k, _ in keys}) != len(keys):
        raise ValueError("duplicate dependency identity")
    packages.sort(key=lambda p: (p["name"], p["versionInfo"], p["SPDXID"]))
    encoded = json.dumps(packages, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(encoded).hexdigest()
    if created is None:
        source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
        stamp = dt.datetime.fromtimestamp(int(source_epoch), dt.timezone.utc) if source_epoch else dt.datetime.now(dt.timezone.utc)
        created = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "GoreeCloud VPN provisional development dependency inventory",
        "documentNamespace": f"https://github.com/GoreeCloud/VPN/spdx/dev-inventory/{sha}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: GoreeCloud VPN offline dependency inventory/1.0"],
            "comment": "Incomplete source-derived dependency inventory, not a production legal SBOM: "
                       "Gradle transitive packages, runtime Qt and native WireGuard library dependencies, "
                       "license obligations and built artifact provenance require separate verification.",
        },
        "packages": packages,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relatedSpdxElement": p["SPDXID"],
             "relationshipType": "DESCRIBES"}
            for p in packages
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="-", help="JSON output path, or - for stdout")
    args = parser.parse_args()
    payload = json.dumps(make_spdx(ROOT), indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(payload, end="")
        return
    path = Path(args.output)
    if path.exists():
        raise SystemExit("refusing to overwrite existing inventory")
    path.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()

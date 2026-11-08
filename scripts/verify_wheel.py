"""Validate the locally built GoreeCloud VPN wheel without installing it."""

from email.parser import BytesParser
from email import policy
from pathlib import Path
import sys
from zipfile import ZipFile


def verify_wheel(directory: Path) -> None:
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one wheel artifact")

    with ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        metadata_files = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise ValueError("expected exactly one wheel metadata file")
        meta = BytesParser(policy=policy.default).parsebytes(
            archive.read(metadata_files[0])
        )
        if meta.get("Name", "").lower().replace("_", "-") != "goreecloud-vpn":
            raise ValueError("incorrect package name")
        if meta.get("License-Expression") != "MIT":
            raise ValueError("missing MIT SPDX metadata")
        if "LICENSE" not in meta.get_all("License-File", []):
            raise ValueError("missing license file declaration")
        license_files = [n for n in names if n.endswith(".dist-info/licenses/LICENSE")]
        if len(license_files) != 1:
            raise ValueError("wheel must contain the repository license")
        license_text = archive.read(license_files[0]).decode("utf-8")
        if not license_text.startswith("MIT License\n"):
            raise ValueError("wheel contains unexpected license text")
        if not any(n.endswith(".dist-info/RECORD") for n in names):
            raise ValueError("wheel RECORD is missing")
        forbidden = (".key", ".pem", ".db", ".sqlite", ".env")
        if any(n.lower().endswith(forbidden) for n in names):
            raise ValueError("a private data file appears in the wheel")


if __name__ == "__main__":
    verify_wheel(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
    print("GoreeCloud VPN wheel license, metadata and file manifest verified")

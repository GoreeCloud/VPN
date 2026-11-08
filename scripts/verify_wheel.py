"""Strict, offline validation of locally built GoreeCloud VPN wheels.

Checks *every* wheel member against RECORD, not merely RECORD's existence.
This detects incomplete/modified local build artifacts, not malicious rebuilds:
a party controlling the wheel may rewrite both content and RECORD. Release
signing / independent provenance checks remain separate requirements.
"""
from __future__ import annotations

import base64
import csv
from email.parser import BytesParser
from email import policy
import hashlib
import hmac
import io
from pathlib import Path, PurePosixPath
import stat
import sys
from zipfile import ZipFile

MAX_MEMBERS = 4096
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
SUPPORTED_HASHES = frozenset({"sha256", "sha384", "sha512"})


def _safe_archive_name(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute()
            and str(path) == value
            and all(component not in {".", "..", ""} for component in path.parts))


def _verify_record(archive: ZipFile, record_path: str, names: set[str]) -> None:
    info = archive.getinfo(record_path)
    if info.file_size > MAX_RECORD_BYTES:
        raise ValueError("oversized wheel RECORD")
    try:
        content = archive.read(record_path).decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("invalid wheel RECORD text") from exc
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(content)):
        if len(row) != 3:
            raise ValueError("RECORD row requires exactly three fields")
        path, expected_hash, size_text = row
        if not _safe_archive_name(path) or path in seen or path not in names:
            raise ValueError("RECORD contains duplicate/unsafe/unpacked path")
        seen.add(path)
        if path == record_path:
            if expected_hash or size_text:
                raise ValueError("RECORD must not hash itself")
            continue
        if not expected_hash or not size_text or not size_text.isascii() or not size_text.isdecimal():
            raise ValueError("RECORD omits required hash or byte count")
        algorithm, separator, encoded_hash = expected_hash.partition("=")
        if not separator or algorithm not in SUPPORTED_HASHES:
            raise ValueError("RECORD requires a secure supported hash algorithm")
        actual = archive.read(path)
        actual_hash = base64.urlsafe_b64encode(
            hashlib.new(algorithm, actual).digest()
        ).decode("ascii").rstrip("=")
        if (not hmac.compare_digest(encoded_hash, actual_hash)
                or int(size_text) != len(actual)):
            raise ValueError("wheel file content differs from RECORD")
    if seen != names:
        raise ValueError("wheel contains an unrecorded file or missing RECORD entry")


def verify_wheel(directory: Path) -> None:
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one wheel artifact")

    with ZipFile(wheels[0]) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_MEMBERS:
            raise ValueError("unexpected wheel member count")
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError("duplicate wheel archive paths")
        if sum(item.file_size for item in entries) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("wheel exceeds build size safety limit")
        for entry in entries:
            if (entry.is_dir() or not _safe_archive_name(entry.filename)
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("wheel contains a directory, unsafe path or symbolic link")
        record_files = [n for n in names if n.endswith(".dist-info/RECORD")]
        if len(record_files) != 1:
            raise ValueError("expected exactly one wheel RECORD")
        record_path = record_files[0]
        dist_info = record_path.rsplit("/", 1)[0]
        metadata_path = f"{dist_info}/METADATA"
        wheel_path = f"{dist_info}/WHEEL"
        license_path = f"{dist_info}/licenses/LICENSE"
        if metadata_path not in names or wheel_path not in names or license_path not in names:
            raise ValueError("wheel must contain METADATA, WHEEL and repository LICENSE")
        if not any(n.startswith("goreecloud_vpn/") for n in names):
            raise ValueError("wheel contains no GoreeCloud VPN module")
        allowed_dist = f"{dist_info}/"
        if any(".dist-info/" in n and not n.startswith(allowed_dist) for n in names):
            raise ValueError("wheel contains another distribution metadata directory")
        if any(n.endswith((".jws", ".p7s")) for n in names):
            raise ValueError("unexpected deprecated RECORD signature file")
        forbidden = (".key", ".pem", ".db", ".sqlite", ".env")
        if any(n.lower().endswith(forbidden) for n in names):
            raise ValueError("private data file appears in the wheel")
        if any(n.startswith("tests/") or n.startswith("scripts/") for n in names):
            raise ValueError("test or build-only script bundled into app wheel")
        _verify_record(archive, record_path, set(names))

        meta = BytesParser(policy=policy.default).parsebytes(
            archive.read(metadata_path)
        )
        if meta.get("Name", "").lower().replace("_", "-") != "goreecloud-vpn":
            raise ValueError("incorrect package name")
        if meta.get("License-Expression") != "MIT":
            raise ValueError("missing MIT SPDX metadata")
        if "LICENSE" not in meta.get_all("License-File", []):
            raise ValueError("missing license file declaration")
        license_text = archive.read(license_path).decode("utf-8")
        if not license_text.startswith("MIT License\n"):
            raise ValueError("wheel contains unexpected license text")


if __name__ == "__main__":
    verify_wheel(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
    print("GoreeCloud VPN wheel RECORD hashes, SPDX, license and file manifest verified")

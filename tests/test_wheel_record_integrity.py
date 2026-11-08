"""Negative wheel RECORD/ZIP integrity tests: no install, no external code."""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
from io import StringIO
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
from zipfile import ZipFile, ZipInfo

VERIFY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_wheel.py"
spec = importlib.util.spec_from_file_location("goreecloud_verify_wheel_test", VERIFY_SCRIPT)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

DIST = "goreecloud_vpn-0.1.0a1.dist-info"
LICENSE = f"{DIST}/licenses/LICENSE"
RECORD = f"{DIST}/RECORD"
METADATA = f"{DIST}/METADATA"
WHEEL = f"{DIST}/WHEEL"
PKG = "goreecloud_vpn/__init__.py"


def default_payloads():
    return {
        PKG: b'__version__ = "0.1.0a1"\n',
        METADATA: (
            b"Metadata-Version: 2.4\nName: goreecloud-vpn\nVersion: 0.1.0a1\n"
            b"License-Expression: MIT\nLicense-File: LICENSE\n\n"
        ),
        WHEEL: b"Wheel-Version: 1.0\nGenerator: setuptools\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        LICENSE: b"MIT License\nCopyright (c) 2026 GoreeCloud contributors\n",
    }


def write_fixture(directory, *, payloads=None, recorded_payloads=None, record_override=None):
    directory = Path(directory)
    members = default_payloads() if payloads is None else payloads
    original = members if recorded_payloads is None else recorded_payloads
    record_output = StringIO()
    writer = csv.writer(record_output, lineterminator="\n")
    for name, contents in original.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode("ascii").rstrip("=")
        writer.writerow([name, "sha256=" + digest, str(len(contents))])
    writer.writerow([RECORD, "", ""])
    record = record_output.getvalue().encode("utf-8") if record_override is None else record_override
    path = directory / "goreecloud_vpn-0.1.0a1-py3-none-any.whl"
    with ZipFile(path, "w") as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)
        archive.writestr(RECORD, record)
    return path


class WheelCompleteRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_synthetic_wheel_passes(self):
        write_fixture(self.path)
        verifier.verify_wheel(self.path)

    def test_modified_license_bytes_stale_record_rejected(self):
        source = default_payloads()
        altered = dict(source, **{LICENSE: source[LICENSE] + b"NOT_RECORDED"})
        write_fixture(self.path, payloads=altered, recorded_payloads=source)
        with self.assertRaisesRegex(ValueError, "differs"):
            verifier.verify_wheel(self.path)

    def test_modified_python_module_stale_record_rejected(self):
        source = default_payloads()
        modified = dict(source, **{PKG: b"import os\nos.system('echo bad')\n"})
        write_fixture(self.path, payloads=modified, recorded_payloads=source)
        with self.assertRaisesRegex(ValueError, "differs"):
            verifier.verify_wheel(self.path)

    def test_file_missing_from_record_fails(self):
        source = default_payloads()
        write_fixture(self.path, recorded_payloads={k: v for k, v in source.items() if k != PKG})
        with self.assertRaisesRegex(ValueError, "unrecorded"):
            verifier.verify_wheel(self.path)

    def test_extra_zip_member_fails(self):
        write_fixture(self.path)
        wheel = next(self.path.glob("*.whl"))
        with ZipFile(wheel, "a") as archive:
            archive.writestr("goreecloud_vpn/unrecorded.py", b"bad")
        with self.assertRaisesRegex(ValueError, "unrecorded"):
            verifier.verify_wheel(self.path)

    def test_sha1_record_for_module_is_rejected(self):
        write_fixture(self.path)
        wheel = next(self.path.glob("*.whl"))
        with ZipFile(wheel) as archive:
            items = {n: archive.read(n) for n in archive.namelist() if n != RECORD}
        lines = StringIO()
        writer = csv.writer(lines, lineterminator="\n")
        for name, payload in items.items():
            algorithm = "sha1" if name == PKG else "sha256"
            digest = base64.urlsafe_b64encode(
                hashlib.new(algorithm, payload).digest()
            ).decode("ascii").rstrip("=")
            writer.writerow([name, algorithm + "=" + digest, len(payload)])
        writer.writerow([RECORD, "", ""])
        write_fixture(self.path, payloads=items, record_override=lines.getvalue().encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "secure"):
            verifier.verify_wheel(self.path)

    def test_record_self_hash_is_forbidden(self):
        write_fixture(self.path)
        wheel = next(self.path.glob("*.whl"))
        with ZipFile(wheel) as archive:
            items = {n: archive.read(n) for n in archive.namelist() if n != RECORD}
            wrong_record = archive.read(RECORD).replace(
                (RECORD + ",,").encode(), (RECORD + ",sha256=AA,4").encode()
            )
        write_fixture(self.path, payloads=items, record_override=wrong_record)
        with self.assertRaisesRegex(ValueError, "must not hash itself"):
            verifier.verify_wheel(self.path)

    def test_duplicate_zip_entry_rejected(self):
        write_fixture(self.path)
        wheel = next(self.path.glob("*.whl"))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with ZipFile(wheel, "a") as archive:
                archive.writestr(PKG, b"duplicate")
        with self.assertRaisesRegex(ValueError, "duplicate wheel"):
            verifier.verify_wheel(self.path)

    def test_traversal_and_private_key_entries_rejected(self):
        for forbidden_path in ("../other.py", "goreecloud_vpn/../escape.py", "goreecloud_vpn/private.key"):
            with self.subTest(forbidden_path=forbidden_path):
                source = default_payloads()
                source[forbidden_path] = b"unexpected content"
                write_fixture(self.path, payloads=source)
                with self.assertRaises(ValueError):
                    verifier.verify_wheel(self.path)

    def test_missing_license_cannot_pass(self):
        source = default_payloads()
        source.pop(LICENSE)
        write_fixture(self.path, payloads=source)
        with self.assertRaisesRegex(ValueError, "LICENSE"):
            verifier.verify_wheel(self.path)

    def test_symbolic_link_archive_member_is_rejected(self):
        write_fixture(self.path)
        wheel = next(self.path.glob("*.whl"))
        with ZipFile(wheel, "a") as archive:
            entry = ZipInfo("goreecloud_vpn/shortcut")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "symlink-target")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            verifier.verify_wheel(self.path)

    def test_no_wheel_and_multiple_wheels_fail(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            verifier.verify_wheel(self.path)
        wheel = write_fixture(self.path)
        (self.path / "second.whl").write_bytes(wheel.read_bytes())
        with self.assertRaisesRegex(ValueError, "exactly one"):
            verifier.verify_wheel(self.path)


if __name__ == "__main__":
    unittest.main()

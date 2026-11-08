"""Repository-level license and package metadata release guard."""

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryLicenseTests(unittest.TestCase):
    def test_repository_has_its_individually_selected_mit_license(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(license_text.startswith("MIT License\n"))
        self.assertIn("Copyright (c) 2026 GoreeCloud contributors", license_text)
        self.assertIn("Permission is hereby granted, free of charge", license_text)
        self.assertIn('THE SOFTWARE IS PROVIDED "AS IS"', license_text)

    def test_package_metadata_and_readme_match_license(self):
        with (ROOT / "pyproject.toml").open("rb") as source:
            metadata = tomllib.load(source)
        self.assertEqual(metadata["project"]["license"], "MIT")
        self.assertEqual(metadata["project"]["name"], "goreecloud-vpn")
        self.assertIn("[MIT License](LICENSE)", (ROOT / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

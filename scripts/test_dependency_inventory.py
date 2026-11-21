import datetime
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("inventory", HERE / "generate_dependency_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_offline_provisional_spdx_has_no_unverified_license_assertion(self):
        doc = inventory.make_spdx(inventory.ROOT, created="2026-11-21T00:00:00Z")
        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc["dataLicense"], "CC0-1.0")
        self.assertTrue(doc["documentNamespace"].startswith("https://github.com/GoreeCloud/VPN/spdx/"))
        ids = [p["SPDXID"] for p in doc["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(doc["relationships"]), len(ids))
        self.assertTrue(all(p["licenseConcluded"] == "NOASSERTION" for p in doc["packages"]))
        self.assertTrue(any(p["name"] == "react" and p["versionInfo"] == "19.2.0" for p in doc["packages"]))
        self.assertTrue(any(p["name"] == "Qt6 Quick" for p in doc["packages"]))
        self.assertTrue(any(p["name"] == "com.wireguard.android:tunnel" for p in doc["packages"]))
        self.assertTrue(any(p["name"] == "GoreeCloud VPN" and
                            p["licenseDeclared"] == "Apache-2.0" for p in doc["packages"]))
        self.assertGreater(len(doc["packages"]), 20)

    def test_timestamp_is_deterministic_when_supplied(self):
        a = inventory.make_spdx(inventory.ROOT, "2026-11-21T00:00:00Z")
        b = inventory.make_spdx(inventory.ROOT, "2026-11-21T00:00:00Z")
        self.assertEqual(a, b)

    def test_go_requirements_are_explicitly_flagged_before_claiming_coverage(self):
        self.assertEqual(inventory.go_packages(inventory.ROOT), [])


if __name__ == "__main__":
    unittest.main()

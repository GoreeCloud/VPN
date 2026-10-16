#!/usr/bin/env python3
"""Synthetic read-only NetBird preflight contract tests."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("preflight-netbird-migration.sh")

class PreflightTests(unittest.TestCase):
    def test_inventory_never_certifies_cutover(self):
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            fixtures = {
                "netbird": "#!/bin/sh\nexit 0\n",
                "systemctl": "#!/bin/sh\n[ \"$*\" = 'is-active --quiet netbird' ]\n",
                "docker": "#!/bin/sh\n[ \"$*\" = 'ps --format {{.Names}}' ] || exit 1\nprintf 'netbird-server\\nnetbird-dashboard\\n'\n",
            }
            for name, contents in fixtures.items():
                program = bin_dir / name
                program.write_text(contents)
                program.chmod(0o755)
            env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
            result = subprocess.run(["bash", str(SCRIPT)], env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("BASELINE STATUS: observed NetBird services available", result.stdout)
            self.assertIn("DECISION: NO-GO", result.stdout)
            (bin_dir / "docker").write_text("#!/bin/sh\nexit 1\n")
            (bin_dir / "docker").chmod(0o755)
            failed = subprocess.run(["bash", str(SCRIPT)], env=env, text=True, capture_output=True, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("BLOCK Docker container inventory unavailable", failed.stdout)
            self.assertIn("DECISION: NO-GO", failed.stdout)

if __name__ == "__main__":
    unittest.main()

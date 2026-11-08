"""Guard against mutable GitHub Actions dependencies or broad CI tokens."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"(?P<owner>[A-Za-z0-9_-]+)/(?P<repo>[A-Za-z0-9_.-]+)@(?P<sha>[a-f0-9]{40})\Z")


class CISupplyChainTests(unittest.TestCase):
    def test_every_external_ci_action_has_full_sha_pin(self):
        workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
        self.assertTrue(workflows, "at least one CI workflow is required")
        found = []
        for workflow in workflows:
            text = workflow.read_text(encoding="utf-8")
            for action in re.findall(r"^\s*-\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE):
                # A local ./action is part of the same reviewed repo.
                if action.startswith("./"):
                    continue
                with self.subTest(workflow=workflow.name, action=action):
                    self.assertRegex(action, PINNED_ACTION)
                found.append(action)
        self.assertTrue(any(x.startswith("actions/checkout@") for x in found))
        self.assertTrue(any(x.startswith("actions/setup-python@") for x in found))

    def test_pr_ci_uses_readonly_repo_token_and_not_privileged_pr_trigger(self):
        workflow = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("  pull_request:\n", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token: write", workflow)

    def test_existing_ci_keeps_test_and_nonpublishing_wheel_gates(self):
        workflow = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m unittest discover -s tests -v", workflow)
        self.assertIn("python -m pip wheel --no-deps --wheel-dir dist .", workflow)
        self.assertIn("python scripts/verify_wheel.py dist", workflow)
        self.assertNotIn("twine upload", workflow)
        self.assertNotIn("docker push", workflow)


if __name__ == "__main__":
    unittest.main()

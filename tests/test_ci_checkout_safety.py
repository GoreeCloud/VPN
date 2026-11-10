"""Offline verification of immutable VPN GitHub Actions and safe checkout."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
PYTHON_SHA = "a26af69be951a213d495a4c3e4e4022e16d87065"
USES = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
CHECKOUT = re.compile(
    r"(?m)^      - uses: actions/checkout@[a-f0-9]{40}[^\n]*\n"
    r"        with:\n"
    r"          persist-credentials: false\s*$"
)


def validate(content: str) -> None:
    expected = ["actions/checkout@" + CHECKOUT_SHA,
                "actions/setup-python@" + PYTHON_SHA]
    if USES.findall(content) != expected:
        raise ValueError("VPN CI action unpinned, duplicated or changed")
    if len(CHECKOUT.findall(content)) != 1:
        raise ValueError("VPN CI persists checkout credentials")


class VPNCheckoutSafetyTests(unittest.TestCase):
    def test_workflow_pinned_and_checkout_ephemeral(self):
        validate(WORKFLOW.read_text(encoding="utf-8"))

    def test_negative_mutations(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for i, mutant in enumerate((
            source.replace(CHECKOUT_SHA, "v4", 1),
            source.replace(PYTHON_SHA, "v5", 1),
            source.replace("persist-credentials: false",
                           "persist-credentials: true", 1),
            source.replace("persist-credentials: false\n", "", 1),
            source + "\n      - uses: other/action@v1\n",
        )):
            with self.subTest(case=i), self.assertRaises(ValueError):
                validate(mutant)


if __name__ == "__main__":
    unittest.main()

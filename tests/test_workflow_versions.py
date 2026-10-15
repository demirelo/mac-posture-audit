"""Prevent the CodeQL version mismatch that broke Dependabot PR scans."""
from pathlib import Path
import re
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


class CodeQLVersions(unittest.TestCase):
    def test_codeql_steps_share_one_pinned_version(self):
        references = []
        for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
            for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
                match = re.match(
                    r"\s*(?:-\s*)?uses:\s*['\"]?github/codeql-action/"
                    r"([^\s@'\"]+)@([^\s'\"#]+)", line)
                if match:
                    action, revision = match.groups()
                    location = f"{workflow.name}:{line_number}"
                    self.assertRegex(revision, r"^[0-9a-f]{40}$", location)
                    references.append((action, revision, location))
        self.assertTrue(any(action == "init" for action, _, _ in references))
        self.assertTrue(any(action == "analyze" for action, _, _ in references))
        self.assertEqual(len({revision for _, revision, _ in references}), 1,
                         "CodeQL steps must update together: " + repr(references))


if __name__ == "__main__":
    unittest.main()

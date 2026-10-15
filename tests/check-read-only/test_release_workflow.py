"""Execute the actual release tag validation with hostile dispatch inputs."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text()
RESOLVE = WORKFLOW.split("      - name: Resolve version tag\n", 1)[1]
RESOLVE = RESOLVE.split("      - name:", 1)[0].split("        run: |\n", 1)[1]
RESOLVE = textwrap.dedent(RESOLVE)


class ReleaseTagTests(unittest.TestCase):
    def run_tag(self, tag, event="workflow_dispatch", ref=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = dict(os.environ, INPUT_TAG=tag, GITHUB_EVENT_NAME=event,
                       GITHUB_REF=ref or "refs/tags/" + tag, GITHUB_OUTPUT=str(output))
            result = subprocess.run(["/bin/bash", "-c", RESOLVE], env=env,
                                    capture_output=True, text=True, cwd=directory)
            contents = output.read_text() if output.exists() else ""
            self.assertFalse((Path(directory) / "EXECUTED").exists())
            return result.returncode, contents

    def test_version_tags(self):
        for tag in ("v1.2.3", "v10.0.2", "v1.2.3-rc.1"):
            for event in ("push", "workflow_dispatch"):
                with self.subTest(tag=tag, event=event):
                    self.assertEqual(self.run_tag(tag, event), (0, "tag=" + tag + "\n"))

    def test_ref_shell_and_output_injection_are_rejected(self):
        for tag in ("main", "refs/heads/main", "../v1.2.3", "--help", "v1.2",
                    "v1.2.3\nsha=attacker", "v1.2.3$(touch EXECUTED)",
                    "v1.2.3`touch EXECUTED`", 'v1.2.3"; touch EXECUTED; #', ""):
            with self.subTest(tag=tag):
                status, output = self.run_tag(tag)
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")

    def test_dispatch_cannot_misstate_build_provenance(self):
        status, output = self.run_tag("v1.2.3", ref="refs/heads/main")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")

    def test_publish_uses_tested_commit_and_does_not_replace_assets(self):
        self.assertIn("needs: validate", WORKFLOW)
        self.assertIn("ref: ${{ needs.validate.outputs.sha }}", WORKFLOW)
        self.assertNotIn("--clobber", WORKFLOW)
        # Values enter commands through environment variables, not shell source.
        scripts = re.findall(r"^        run: \|\n((?:(?: {10}.*)?\n)*)", WORKFLOW, re.M)
        self.assertGreater(len(scripts), 2)
        for script in scripts:
            self.assertNotIn("${{", script)


if __name__ == "__main__":
    unittest.main()

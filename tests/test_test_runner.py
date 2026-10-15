"""Dependency checks must stop before scans when a tool is missing or unusable."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "test.sh"


class TestRunnerPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.trace = self.directory / "probes"
        # Keep the test PATH closed: a real installed tool must not fill a gap.
        (self.directory / "dirname").symlink_to("/usr/bin/dirname")
        for tool in ("bats", "shellcheck", "shfmt", "python3"):
            self.write_tool(tool)

    def write_tool(self, tool, version_status=0, python_status=0):
        path = self.directory / tool
        path.write_text(
            "#!/bin/bash\n"
            "printf '%s\\n' '" + tool + ":'\"$1\" >> \"$PROBE_LOG\"\n"
            "if [[ \"$1\" == --version ]]; then\n"
            "  printf '%s\\n' 'test version'\n"
            "  exit " + str(version_status) + "\n"
            "fi\n"
            "if [[ \"$1\" == -c ]]; then exit " + str(python_status) + "; fi\n"
            "exit 99\n"
        )
        path.chmod(0o700)

    def run_preflight(self, *arguments):
        env = dict(os.environ, PATH=str(self.directory), PROBE_LOG=str(self.trace))
        result = subprocess.run(["/bin/bash", str(RUNNER), *arguments], env=env,
                                capture_output=True, text=True, timeout=10)
        probes = self.trace.read_text().splitlines() if self.trace.exists() else []
        return result, probes

    def test_check_tools_only_probes_dependencies(self):
        result, probes = self.run_preflight("--check-tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(probes, ["bats:--version", "shellcheck:--version",
                                  "shfmt:--version", "python3:--version", "python3:-c"])
        self.assertNotIn("Safety fixtures", result.stdout)

    def test_unusable_tool_has_actionable_exit_two(self):
        self.write_tool("shellcheck", version_status=126)
        result, probes = self.run_preflight("--check-tools")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Test tool cannot run: shellcheck", result.stderr)
        self.assertIn(str(self.directory / "shellcheck"), result.stderr)
        self.assertIn("first in PATH", result.stderr)
        self.assertEqual(probes, ["bats:--version", "shellcheck:--version"])

    def test_missing_tool_stops_before_scans(self):
        (self.directory / "bats").unlink()
        result, probes = self.run_preflight("--check-tools")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Missing test tool: bats", result.stderr)
        self.assertEqual(probes, [])

    def test_unsupported_python_stops_before_scans(self):
        self.write_tool("python3", python_status=1)
        result, probes = self.run_preflight("--check-tools")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires Python 3.9 or later", result.stderr)
        self.assertEqual(probes[-1], "python3:-c")

    def test_unknown_argument_cannot_start_tests(self):
        result, probes = self.run_preflight("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)
        self.assertEqual(probes, [])


if __name__ == "__main__":
    unittest.main()

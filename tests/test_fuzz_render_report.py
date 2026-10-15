"""Exercise the fuzz target's error boundary without installing Atheris."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SEED_DIRECTORY = ROOT / ".clusterfuzzlite" / "seed_corpus"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = load_module("_fuzz_test_renderer", ROOT / "tools" / "render_report.py")
atheris_stub = types.ModuleType("atheris")
atheris_stub.instrument_imports = contextlib.nullcontext
atheris_stub.instrument_func = Mock(side_effect=lambda function: function)
with patch.dict(sys.modules, {"atheris": atheris_stub, "render_report": report}):
    # Loading the checkout harness can add tools/ to sys.path. Keep that
    # import-time adjustment local to these tests.
    with patch.object(sys, "path", sys.path.copy()):
        fuzz = load_module("_fuzz_test_target", ROOT / ".clusterfuzzlite" / "fuzz_render_report.py")


VALID_DOCUMENT = {
    "host": "<script>example</script>\u00e9",
    "macos": "27.0.1",
    "arch": "arm64",
    "summary": {"pass": 0, "warn": 1, "fail": 0, "skip": 0, "total": 1},
    "executive_verdict": {"tier": "high", "profile": "normal", "text": "Review this."},
    "results": [{"id": "test.check.one", "status": "warn", "label": "Review <setting>",
                 "hint": "Use \"Settings\" & review."}],
    "top_risks": [{"id": "test.check.one", "status": "warn", "label": "Review <setting>",
                   "tier": "high", "rank": 1}],
}
VALID_BYTES = json.dumps(VALID_DOCUMENT, ensure_ascii=False).encode("utf-8")


class FuzzTargetTests(unittest.TestCase):
    def test_entry_point_is_instrumented_before_input_rejection(self):
        atheris_stub.instrument_func.assert_called_once_with(fuzz.TestOneInput)

    def test_valid_document_reaches_loader_validator_and_renderer(self):
        with patch.object(report, "read_document", wraps=report.read_document) as load:
            with patch.object(report, "validate", wraps=report.validate) as validate:
                with patch.object(report, "render", wraps=report.render) as render:
                    fuzz.TestOneInput(VALID_BYTES)
        load.assert_called_once()
        validate.assert_called_with(VALID_DOCUMENT)
        render.assert_called_once_with(VALID_DOCUMENT)

    def test_strict_loader_rejects_hostile_bytes_before_rendering(self):
        cases = (
            b'{"results":[],"host":"\xff"}',
            b'{"results":[],"results":[]}',
            b'{"results":[],"metadata":{"key":1,"key":2}}',
            b'{"results":[],"metadata":NaN}',
            b'{"results":[],"metadata":Infinity}',
            b'{"results":[],"metadata":1e999}',
            b'{"results":[],"metadata":' + b"9" * 129 + b"}",
            b'{"results":[]} trailing',
        )
        for data in cases:
            with self.subTest(data=data):
                with patch.object(report, "render") as render:
                    fuzz.TestOneInput(data)
                render.assert_not_called()

    def test_input_size_limit_is_exercised(self):
        with patch.object(report, "MAX_INPUT_BYTES", 16):
            with patch.object(report, "render") as render:
                fuzz.TestOneInput(b'{"results":[]}' + b" " * 17)
        render.assert_not_called()

    def test_deeply_nested_additive_metadata_does_not_crash(self):
        data = b'{"results":[],"metadata":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
        # Parser depth limits vary across Python versions. The harness may
        # reject this with RecursionError or render it with metadata ignored.
        fuzz.TestOneInput(data)

    def test_loader_recursion_error_is_an_expected_parse_rejection(self):
        with patch.object(report, "read_document", side_effect=RecursionError("parser depth")) as load:
            with patch.object(report, "validate") as validate:
                with patch.object(report, "render") as render:
                    fuzz.TestOneInput(VALID_BYTES)
        load.assert_called_once()
        validate.assert_not_called()
        render.assert_not_called()

    def test_schema_rejections_do_not_reach_renderer(self):
        cases = (
            b"null",
            b"[]",
            b"{}",
            b'{"results":[{}]}',
            b'{"results":[],"summary":{"pass":"<script>"}}',
            b'{"results":[],"host":"\\ud800"}',
            b'{"results":[],"top_risks":[{}]}',
        )
        for data in cases:
            with self.subTest(data=data):
                with patch.object(report, "render") as render:
                    fuzz.TestOneInput(data)
                render.assert_not_called()

    def test_unexpected_loader_errors_are_visible(self):
        for error in (KeyError, TypeError, AttributeError, RuntimeError):
            with self.subTest(error=error):
                with patch.object(report, "read_document", side_effect=error("loader bug")):
                    with self.assertRaises(error):
                        fuzz.TestOneInput(VALID_BYTES)

    def test_unexpected_validation_errors_are_visible(self):
        for error in (KeyError, TypeError, AttributeError, RuntimeError, RecursionError):
            with self.subTest(error=error):
                with patch.object(report, "validate", side_effect=error("validation bug")):
                    with self.assertRaises(error):
                        fuzz.TestOneInput(VALID_BYTES)

    def test_all_rendering_errors_remain_visible_after_validation(self):
        for error in (KeyError, TypeError, AttributeError, RuntimeError, ValueError, RecursionError):
            with self.subTest(error=error):
                with patch.object(report, "render", side_effect=error("render bug")):
                    with self.assertRaises(error):
                        fuzz.TestOneInput(VALID_BYTES)

    def test_output_must_be_utf8_encodable(self):
        with patch.object(report, "render", return_value="\ud800"):
            with self.assertRaises(UnicodeEncodeError):
                fuzz.TestOneInput(VALID_BYTES)

    def test_seed_reports_reach_renderer(self):
        seeds = sorted(SEED_DIRECTORY.glob("*.json"))
        self.assertGreaterEqual(len(seeds), 2)
        for seed in seeds:
            with self.subTest(seed=seed.name):
                data = seed.read_bytes()
                document = report.read_document(io.BytesIO(data))
                report.validate(document)
                with patch.object(report, "render", wraps=report.render) as render:
                    fuzz.TestOneInput(data)
                render.assert_called_once_with(document)
        minimal = json.loads((SEED_DIRECTORY / "minimal-v1.json").read_text())
        full = json.loads((SEED_DIRECTORY / "full-v1.json").read_text())
        self.assertEqual(minimal["results"], [])
        self.assertEqual({row["status"] for row in full["results"]}, set(report.STATUS_LABEL))
        self.assertEqual({row["tier"] for row in full["top_risks"]}, set(report.TIER_ORDER))

    def test_build_packages_exact_seed_bytes_next_to_target(self):
        # Exercise the real build script and ZIP writer. Only the container's
        # unavailable compiler helper is replaced; no Atheris install is needed.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source with spaces"
            project = source / "mac-posture-audit"
            cluster = project / ".clusterfuzzlite"
            cluster.mkdir(parents=True)
            (project / "tools").mkdir()
            shutil.copy2(ROOT / "tools" / "render_report.py", project / "tools" / "render_report.py")
            for name in ("build.sh", "fuzz_render_report.py"):
                shutil.copy2(ROOT / ".clusterfuzzlite" / name, cluster / name)
            shutil.copytree(SEED_DIRECTORY, cluster / "seed_corpus")
            output = base / "output with spaces"
            output.mkdir()
            binaries = base / "bin"
            binaries.mkdir()
            (binaries / "python3").symlink_to(sys.executable)
            compiler = binaries / "compile_python_fuzzer"
            compiler.write_text('#!/bin/sh\nset -eu\ntest -f "$1"\nprintf "%s" "$1" > "$OUT/compiled-target"\n')
            compiler.chmod(0o755)
            env = dict(os.environ, SRC=str(source), OUT=str(output),
                       PATH=str(binaries) + os.pathsep + "/usr/bin:/bin")
            archive_path = output / "fuzz_render_report_seed_corpus.zip"
            # A rebuild must replace obsolete members, not retain old inputs.
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("obsolete.txt", "not a seed")
            result = subprocess.run(["/bin/bash", "-eu", str(cluster / "build.sh")],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "compiled-target").read_text(), str(cluster / "fuzz_render_report.py"))
            expected = {seed.name: seed.read_bytes() for seed in SEED_DIRECTORY.glob("*.json")}
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(set(archive.namelist()), set(expected))
                for name, data in expected.items():
                    self.assertEqual(archive.read(name), data)


if __name__ == "__main__":
    unittest.main()

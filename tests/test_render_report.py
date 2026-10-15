"""Hermetic report security tests. Run with python3 -m unittest discover -s tests."""

import copy
import contextlib
from html.parser import HTMLParser
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


RENDERER = Path(__file__).resolve().parents[1] / "tools" / "render_report.py"
SPEC = importlib.util.spec_from_file_location("render_report", RENDERER)
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


def fixture():
    return {
        "host": "<HOST>", "macos": "26.1", "arch": "arm64",
        "summary": {"pass": 1, "warn": 0, "fail": 1, "skip": 0, "total": 2},
        "executive_verdict": {
            "profile": "standard", "tier": "high", "text": "Review one failure.",
            "top_counts": {"urgent": 0, "high": 1, "medium": 0, "low": 0},
        },
        "top_risks": [{"rank": 1, "tier": "high", "id": "test.check.two",
                       "status": "fail", "label": "Second check", "hint": "Review it"}],
        "results": [
            {"id": "test.check.one", "status": "pass", "label": "First check", "hint": ""},
            {"id": "test.check.two", "status": "fail", "label": "Second check", "hint": "Review it"},
        ],
    }


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class RenderTests(unittest.TestCase):
    def test_valid_report_is_self_contained_and_shows_hints(self):
        doc = fixture()
        original = copy.deepcopy(doc)
        output = report.render(doc)
        self.assertIn("1 pass · 0 warn · 1 fail · 0 skip (2 total)", output)
        self.assertIn('class="hint">Review it</div>', output)
        self.assertIn("Action priority: high", output)
        self.assertEqual(doc, original)
        for tag, attrs in Elements(output).elements:
            self.assertNotIn(tag, ("script", "iframe", "form", "img", "link", "base"))
            self.assertFalse(set(attrs) & {"src", "href"})

    def test_all_text_fields_escape_html(self):
        payload = '<script>alert("x")</script><img src=x onerror=alert(1)>&\''
        doc = fixture()
        for field in ("host", "macos", "arch"):
            doc[field] = payload
        doc["executive_verdict"].update(profile=payload, text=payload)
        doc["results"][1].update(id=payload, label=payload, hint=payload)
        doc["top_risks"][0].update(id=payload, label=payload, hint=payload)
        output = report.render(doc)
        self.assertIn(report.esc(payload), output)
        self.assertNotIn(payload, output)
        for tag, attrs in Elements(output).elements:
            self.assertNotIn(tag, ("script", "img"))
            self.assertFalse(any(key.startswith("on") for key in attrs))

    def test_summary_html_injection_is_rejected(self):
        for key in ("pass", "warn", "fail", "skip", "total"):
            with self.subTest(key=key):
                doc = fixture()
                doc["summary"][key] = "<script>alert(1)</script>"
                with self.assertRaisesRegex(ValueError, "summary"):
                    report.render(doc)

    def test_csp_blocks_active_content_and_network(self):
        metas = [attrs for tag, attrs in Elements(report.render(fixture())).elements if tag == "meta"]
        policy = next(attrs["content"] for attrs in metas
                      if attrs.get("http-equiv") == "Content-Security-Policy")
        for directive in ("default-src 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, policy)
        self.assertIn({"name": "referrer", "content": "no-referrer"}, metas)

    def test_top_zero_never_claims_risks_are_absent(self):
        doc = fixture()
        doc["top_risks"] = []
        output = report.render(doc)
        self.assertNotIn("No warnings or failures", output)
        self.assertIn("Review the warnings and failures below", output)

    def test_legacy_input_gets_real_counts_and_unknown_priority(self):
        doc = {"results": fixture()["results"]}
        output = report.render(doc)
        self.assertIn("1 pass · 0 warn · 1 fail", output)
        self.assertIn("Action priority: not provided", output)

    def test_empty_input_has_no_findings(self):
        output = report.render({"results": []})
        self.assertIn("No warnings or failures", output)
        self.assertIn("0 total", output)

    def test_invalid_shapes_raise_value_error(self):
        invalid = [None, [], {}, {"results": None}, {"results": {}}, {"results": [None]}]
        for field in ("summary", "executive_verdict", "top_risks"):
            for value in (None, "string", 42):
                doc = fixture()
                doc[field] = value
                invalid.append(doc)
        for field in ("id", "label", "hint", "status"):
            doc = fixture()
            doc["results"][0][field] = []
            invalid.append(doc)
        for doc in invalid:
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                report.render(doc)

    def test_inconsistent_summary_is_rejected(self):
        for key in ("pass", "warn", "fail", "skip", "total"):
            doc = fixture()
            doc["summary"][key] += 1
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "does not match"):
                report.render(doc)

    def test_boolean_or_negative_counts_are_rejected(self):
        for value in (True, False, -1, 1.0):
            doc = fixture()
            doc["summary"]["pass"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                report.render(doc)

    def test_invalid_status_or_priority_cannot_enter_attributes(self):
        payload = 'fail" onclick="alert(1)'
        for location, key in (("results", "status"), ("top_risks", "tier"),
                              ("executive_verdict", "tier")):
            doc = fixture()
            target = doc[location] if location == "executive_verdict" else doc[location][0]
            target[key] = payload
            with self.subTest(location=location), self.assertRaises(ValueError):
                report.render(doc)

    def test_duplicate_ids_are_rejected(self):
        doc = fixture()
        doc["results"][1]["id"] = doc["results"][0]["id"]
        with self.assertRaisesRegex(ValueError, "duplicates"):
            report.render(doc)

    def test_risks_must_match_results_and_have_valid_ranks(self):
        for key, value in (("id", "unknown.id"), ("id", "test.check.one"),
                           ("status", "warn"), ("label", "Different"), ("rank", 0),
                           ("rank", 2), ("rank", True), ("rank", "1"), ("tier", [])):
            doc = fixture()
            doc["top_risks"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                report.render(doc)

    def test_none_priority_cannot_hide_failures(self):
        doc = fixture()
        doc["executive_verdict"]["tier"] = "none"
        with self.assertRaisesRegex(ValueError, "contain risks"):
            report.render(doc)

    def test_surrogate_and_excessive_text_are_rejected(self):
        for value in ("\ud800", "x" * (report.MAX_TEXT_LENGTH + 1)):
            doc = fixture()
            doc["host"] = value
            with self.assertRaises(ValueError):
                report.render(doc)

    def test_row_limit_is_enforced_before_processing(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            report.render({"results": [None] * (report.MAX_ROWS + 1)})

    def test_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (b'{"results":[],"results":[]}', b'{"results":[],"x":{"a":1,"a":2}}',
                    b'{"results":[],"x":NaN}', b'{"results":[],"x":Infinity}',
                    b'{"results":[],"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                report.read_document(io.BytesIO(raw))

    def test_large_numeric_tokens_are_rejected_before_conversion(self):
        for number in (b"9" * 129, b"0." + b"9" * 129, b"1e" + b"9" * 129):
            with self.subTest(number=number), self.assertRaisesRegex(ValueError, "long JSON number"):
                report.read_document(io.BytesIO(b'{"results":[],"x":' + number + b'}'))

    def test_byte_limit_is_enforced(self):
        with patch.object(report, "MAX_INPUT_BYTES", 16):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                report.read_document(io.BytesIO(b" " * 17))


class CommandTests(unittest.TestCase):
    def run_report(self, raw=None, *args):
        if raw is None:
            raw = json.dumps(fixture()).encode()
        return subprocess.run([sys.executable, str(RENDERER), *args], input=raw,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_cli_renders_stdin(self):
        result = self.run_report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(b"<!doctype html>"))
        self.assertEqual(result.stderr, b"")

    def test_cli_rejects_hostile_input_without_html_or_tracebacks(self):
        doc = fixture()
        doc["summary"]["pass"] = "<script>alert(1)</script>"
        for raw in (json.dumps(doc).encode(), b'{"results":[null]}', b'{"results":null}',
                    b'[]', b'{"results":[],"host":"\xff"}', b'[' * 2000 + b']' * 2000):
            with self.subTest(raw=raw[:50]):
                result = self.run_report(raw)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"render_report: invalid input:", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_reads_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "posture.json"
            doc = fixture()
            doc["host"] = "Zürich"
            source.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            result = self.run_report(b"", str(source))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Zürich".encode(), result.stdout)

    def test_stdout_is_utf8_even_with_an_ascii_io_locale(self):
        doc = fixture()
        doc["host"] = "Zürich"
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        result = subprocess.run([sys.executable, str(RENDERER)], env=env,
                                input=json.dumps(doc).encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Zürich".encode(), result.stdout)

    def test_closed_output_pipe_is_a_clean_error(self):
        process = subprocess.Popen([sys.executable, str(RENDERER)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdout.close()
        _, stderr = process.communicate(json.dumps(fixture()).encode())
        self.assertEqual(process.returncode, 2, stderr)
        self.assertIn(b"output pipe closed", stderr)
        self.assertNotIn(b"Traceback", stderr)
        self.assertNotIn(b"Exception ignored", stderr)

    def test_output_is_private_even_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.html"
            old_umask = os.umask(0)
            try:
                result = self.run_report(None, "--output", str(target))
            finally:
                os.umask(old_umask)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertTrue(target.read_text(encoding="utf-8").startswith("<!doctype html>"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS inherited ACL regression")
    def test_output_removes_inherited_allow_acl_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "reports"
            parent.mkdir(mode=0o700)
            subprocess.run(["/bin/chmod", "+a", "everyone allow read,file_inherit", str(parent)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            target = parent / "report.html"
            result = self.run_report(None, "--output", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            acl = subprocess.run(["/bin/ls", "-le", str(target)], check=True,
                                 stdout=subprocess.PIPE, text=True).stdout
            self.assertNotIn("allow read", acl)
            self.assertEqual(len(acl.splitlines()), 1, acl)
            self.assertTrue(target.read_text(encoding="utf-8").startswith("<!doctype html>"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS inherited ACL regression")
    def test_acl_removal_failure_does_not_write_report_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input.json"
            source.write_text(json.dumps(fixture()), encoding="utf-8")
            target = Path(tmp) / "report.html"
            error = subprocess.CalledProcessError(1, "/bin/chmod")
            stderr = io.StringIO()
            with patch.object(report.subprocess, "run", side_effect=error):
                with contextlib.redirect_stderr(stderr):
                    status = report.main([str(RENDERER), str(source), "--output", str(target)])
            self.assertEqual(status, 2)
            self.assertIn("could not remove inherited ACL", stderr.getvalue())
            self.assertEqual(target.read_bytes(), b"")

    def test_output_refuses_existing_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original"
            original.write_text("keep me", encoding="utf-8")
            link = Path(tmp) / "link"
            link.symlink_to(original)
            dangling = Path(tmp) / "dangling"
            dangling.symlink_to(Path(tmp) / "missing")
            for path in (original, link, dangling):
                with self.subTest(path=path):
                    result = self.run_report(None, "--output", str(path))
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(b"Traceback", result.stderr)
                    self.assertEqual(original.read_text(encoding="utf-8"), "keep me")
            self.assertTrue(link.is_symlink())
            self.assertTrue(dangling.is_symlink())
            self.assertFalse((Path(tmp) / "missing").exists())

    def test_invalid_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.html"
            result = self.run_report(b"{}", "--output", str(target))
            self.assertEqual(result.returncode, 2)
            self.assertFalse(target.exists())

    def test_missing_input_or_output_parent_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "missing")
            for args in ((missing,), ("--output", missing + "/report.html")):
                result = self.run_report(None, *args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()

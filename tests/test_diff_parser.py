"""Bounded, deterministic differential checks for the shell JSON reader.

Only source the shell helper; never run an audit or read machine configuration.
Python's JSON decoder supplies the expected rows for generated valid documents.
"""

import json
import os
from pathlib import Path
import random
import signal
import subprocess
import unittest


AUDITOR = Path(__file__).resolve().parents[1] / "mac-posture-audit.sh"
STATUSES = ("pass", "warn", "fail", "skip")
TEXT = (
    'braces },{ and "id":"decoy.id","status":"fail"',
    'backslash \\ and slash / and quote "',
    "escaped controls: \b\f\n\r\t\x01\x1f",
    "café Zürich 中文 🔒",
    "valid JSON DEL: \x7f",
    "UTF-8 boundaries: \u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff",
    "true false null -12.50e+2 [ ] { } : ,",
    "",
)


def shuffled_object(rng, pairs):
    pairs = list(pairs)
    rng.shuffle(pairs)
    return dict(pairs)


def nested_metadata(rng, depth):
    if depth == 0:
        return rng.choice((None, True, False, -17, 0, 3.125, 1.5e-21, rng.choice(TEXT)))
    if rng.randrange(2):
        return [nested_metadata(rng, depth - 1) for _ in range(rng.randrange(4))]
    return shuffled_object(rng, (
        ("id", "metadata.decoy.id"),
        ("status", rng.choice(STATUSES)),
        ("results", nested_metadata(rng, depth - 1)),
        ("payload", nested_metadata(rng, depth - 1)),
    ))


def generated_documents():
    rng = random.Random(0xA0D17)
    for case in range(24):
        rows = []
        for row in range(case % 7):
            rows.append(shuffled_object(rng, (
                ("id", f"fixture.case_{case:02d}.row_{row:02d}"),
                ("status", rng.choice(STATUSES)),
                ("label", TEXT[(case + row) % len(TEXT)]),
                ("hint", rng.choice(TEXT)),
                ("metadata", nested_metadata(rng, 3)),
            )))
        doc = shuffled_object(rng, (
            ("results", rows),
            ("host", "fixture-host"),
            ("metadata", nested_metadata(rng, 3)),
            ("label", TEXT[case % len(TEXT)]),
            ("summary", {status: sum(row["status"] == status for row in rows)
                         for status in STATUSES}),
        ))
        raw = json.dumps(doc, ensure_ascii=bool(case % 2),
                         indent=(None, 1, 2)[case % 3], allow_nan=False)
        if case % 3 == 0:
            raw = raw.replace('"results"', '"res\\u0075lts"')
            raw = raw.replace('"id"', '"\\u0069d"')
            raw = raw.replace('"pass"', '"p\\u0061ss"')
        if case % 4 == 0:
            raw = raw.replace("/", "\\/")
        # JSON permits leading/trailing space, tab, LF, and CR.
        yield case, (" \t\r\n" + raw + "\r\n\t ").encode("utf-8")


class DiffParserTests(unittest.TestCase):
    def parse_rows(self, raw, timeout=5):
        env = dict(os.environ, PATH="/usr/bin:/bin:/usr/sbin:/sbin")
        # -p blocks BASH_ENV and imported functions. The main source guard
        # prevents any audit execution. Input goes only to the parsing helper.
        process = subprocess.Popen(
            ["/bin/bash", "-p", "-c", 'source "$1"; _diff_parse_rows differential',
             "_", str(AUDITOR)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(raw, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Bash waits for awk. Killing only Bash leaves a slow parser alive
            # with inherited pipes, so terminate the complete test process group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def assert_metadata(self, metadata, *, prefix=b"", timeout=5, error=None):
        raw = (prefix + b'{"results":[{"id":"fixture.valid.row","status":"pass"}],'
               b'"metadata":' + metadata + b'}')
        parsed = self.parse_rows(raw, timeout=timeout)
        if error is None:
            self.assertEqual(parsed.returncode, 0, parsed.stderr.decode("utf-8"))
            self.assertEqual(parsed.stdout, b"fixture.valid.row pass\n")
            self.assertEqual(parsed.stderr, b"")
        else:
            self.assertEqual(parsed.returncode, 2)
            self.assertEqual(parsed.stdout, b"")
            self.assertIn(error, parsed.stderr)

    def test_generated_valid_documents_match_python_rows(self):
        for case, raw in generated_documents():
            with self.subTest(case=case):
                doc = json.loads(raw)
                expected = "".join(f'{row["id"]} {row["status"]}\n'
                                   for row in doc["results"]).encode("ascii")
                parsed = self.parse_rows(raw)
                self.assertEqual(parsed.returncode, 0, parsed.stderr.decode("utf-8"))
                self.assertEqual(parsed.stderr, b"")
                self.assertEqual(parsed.stdout, expected)

    def test_truncated_generated_documents_emit_no_partial_rows(self):
        # A valid row precedes the truncation. No valid prefix may escape when
        # parsing fails later in a nested value or the enclosing document.
        raw = json.dumps({
            "results": [{"id": "fixture.valid.row", "status": "pass"}],
            "metadata": {"escaped": 'text \\"', "nested": [None, {"n": 42}]},
        }).encode("ascii")
        for malformed in (raw[:-1], raw[:-4], raw + b"{}", raw + b" false"):
            with self.subTest(raw=malformed):
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(malformed)
                parsed = self.parse_rows(malformed)
                self.assertEqual(parsed.returncode, 2)
                self.assertEqual(parsed.stdout, b"")
                self.assertIn(b"--diff: differential", parsed.stderr)

    def test_nested_duplicate_keys_reject_valid_row_prefix(self):
        # Python normally accepts duplicates. Configure it to use the same
        # fail-closed rule, including aliases encoded with Unicode escapes.
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        prefix = b'{"results":[{"id":"fixture.valid.row","status":"pass"}],"metadata":'
        for duplicate in (b'{"a":1,"\\u0061":2}',
                          b'[{"nested":{"x":null,"x":false}}]'):
            raw = prefix + duplicate + b'}'
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "duplicate key"):
                    json.loads(raw, object_pairs_hook=unique_object)
                parsed = self.parse_rows(raw)
                self.assertEqual(parsed.returncode, 2)
                self.assertEqual(parsed.stdout, b"")
                self.assertIn(b"duplicate", parsed.stderr)

    def test_raw_nul_bytes_cannot_hide_invalid_input(self):
        valid = b'{"results":[{"id":"fixture.valid.row","status":"pass"}]}'
        malformed = (
            valid + b"\x00junk\n",
            valid + b"\x00" + valid,
            valid + b"\n\x00junk\n",
            b"\x00" + valid,
            valid.replace(b"fixture.valid.row", b"fixture\x00.valid.row"),
        )
        for raw in malformed:
            for padding in (0, 1023, 1024, 1025):
                with self.subTest(raw=raw, padding=padding):
                    payload = b" " * padding + raw
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(payload.decode("utf-8"))
                    parsed = self.parse_rows(payload)
                    self.assertEqual(parsed.returncode, 2)
                    self.assertEqual(parsed.stdout, b"")

    def test_tokens_cross_input_chunk_boundaries(self):
        tokens = (
            b'"a\\n\\t\\\\\\/\\\"b"', b'"\\uD83D\\uDD12"',
            '"é\u07ff\u0800\ud7ff\ue000\U00010000\U0010ffff"'.encode("utf-8"),
            b'-1234.567e-8', b'true', b'false', b'null', b'{"\\u0061":0}',
        )
        header = b'{"results":[{"id":"fixture.valid.row","status":"pass"}],"metadata":'
        for token in tokens:
            for offset in range(1, len(token) + 1):
                with self.subTest(token=token, offset=offset):
                    self.assert_metadata(token, prefix=b" " * (1024 - len(header) - offset))

    def test_invalid_tokens_at_chunk_boundaries_emit_no_rows(self):
        tokens = (
            b'"\xc0\xaf"', b'"\xe0\x80\x80"', b'"\xed\xa0\x80"',
            b'"\xf0\x80\x80\x80"', b'"\xf4\x90\x80\x80"',
            b'"\xf5\x80\x80\x80"', b'"\x80"', b'"\xe2\x82"',
            b'"\t"', b'"\x00"', b'"\\u0000"', b'"\\ud800"',
            b'"\\udc00"', b'"\\ud800\\u0041"', b'"\\u12xz"',
            b'"\\x41"', b'01', b'1.', b'1e+', b'tru',
        )
        header = b'{"results":[{"id":"fixture.valid.row","status":"pass"}],"metadata":'
        for token in tokens:
            for offset in range(1, len(token) + 1):
                with self.subTest(token=token, offset=offset):
                    self.assert_metadata(token, prefix=b" " * (1024 - len(header) - offset),
                                         error=b"--diff: differential")

    def test_large_metadata_completes_on_stock_awk(self):
        # The old whole-document cursor was already slow at 64 KiB. These
        # near-limit documents exercise long lines, UTF-8, numbers, escapes,
        # and millions of short lines with generous fixed deadlines. The
        # helper PATH selects /usr/bin/awk even when GNU awk is installed.
        size = 8 * 1024 * 1024 - 1024
        for name, metadata in (
            ("ascii", b'"' + b'x' * size + b'"'),
            ("utf8", b'"' + b'\xc3\xa9' * (size // 2) + b'"'),
            ("escaped", b'"' + b'\\n' * (size // 2) + b'"'),
            ("number", b'1' * size),
            ("blank_lines", b'\n' * size + b'null'),
        ):
            with self.subTest(name=name):
                self.assert_metadata(metadata, timeout=20)

    def test_long_captured_strings_and_duplicate_aliases(self):
        key = b"x" * (1024 * 1024)
        self.assert_metadata(b'{"' + key + b'":null}', timeout=10)
        # Both keys decode to the same long string across many chunks.
        self.assert_metadata(b'{"' + key + b'":0,"' + key[:-1] + b'\\u0078":1}',
                             timeout=10, error=b"duplicate object member")
        self.assert_metadata(b'{"' + b'\\n' * (512 * 1024) + b'":null}', timeout=10)
        raw = b'{"results":[{"id":"' + key + b'","status":"pass"}]}'
        parsed = self.parse_rows(raw, timeout=10)
        self.assertEqual(parsed.returncode, 0, parsed.stderr.decode("utf-8"))
        self.assertEqual(parsed.stdout, key + b" pass\n")

    def test_total_value_limit_accepts_boundary_and_rejects_excess(self):
        # Root, results, row, ID, status, and metadata account for six values.
        values = 250000 - 6
        self.assert_metadata(b'[' + b'0,' * (values - 1) + b'0]', timeout=10)
        self.assert_metadata(b'[' + b'0,' * values + b'0]', timeout=10,
                             error=b"250000-value limit")
        # Many distinct members also consume the value budget; the limit is
        # not restricted to arrays or result rows.
        metadata = b'{' + b','.join(b'"k%d":0' % i for i in range(values + 1)) + b'}'
        self.assert_metadata(metadata, timeout=15, error=b"250000-value limit")

    def test_ten_thousand_useful_rows_fit_limits(self):
        rows = [{"id": f"fixture.row_{i}", "status": STATUSES[i % 4],
                 "label": TEXT[i % len(TEXT)], "hint": "fixture hint",
                 "evidence": {"count": i, "known": True}}
                for i in range(10000)]
        raw = json.dumps({"results": rows}, ensure_ascii=False).encode("utf-8")
        parsed = self.parse_rows(raw, timeout=15)
        self.assertEqual(parsed.returncode, 0, parsed.stderr.decode("utf-8"))
        expected = "".join(f'{row["id"]} {row["status"]}\n' for row in rows).encode("ascii")
        self.assertEqual(parsed.stdout, expected)

    def test_oversize_document_and_late_error_emit_no_rows(self):
        self.assert_metadata(b'"' + b'x' * (8 * 1024 * 1024) + b'"', timeout=10,
                             error=b"8 MiB input limit")
        self.assert_metadata(b'"' + b'x' * (4 * 1024 * 1024) + b'\\x"', timeout=10,
                             error=b"invalid string escape")


if __name__ == "__main__":
    unittest.main()

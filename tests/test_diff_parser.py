"""Bounded, deterministic differential checks for the shell JSON reader.

Only source the shell helper; never run an audit or read machine configuration.
Python's JSON decoder supplies the expected rows for generated valid documents.
"""

import json
import os
from pathlib import Path
import random
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
    def parse_rows(self, raw):
        env = dict(os.environ, PATH="/usr/bin:/bin:/usr/sbin:/sbin")
        # -p blocks BASH_ENV and imported functions. The main source guard
        # prevents any audit execution. Input goes only to the parsing helper.
        return subprocess.run(
            ["/bin/bash", "-p", "-c", 'source "$1"; _diff_parse_rows differential',
             "_", str(AUDITOR)],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=5, check=False,
        )

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


if __name__ == "__main__":
    unittest.main()

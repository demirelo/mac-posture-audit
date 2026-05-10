#!/usr/bin/env python3
"""Stdlib-only validator for the mac-posture-audit JSON schema.

macOS Python ships with the json module but not jsonschema, so the schema is
hand-checked: required keys, types, enums, and the counter-parity invariant.

Usage: validate_schema.py path/to/posture.json
Exit:  0 if valid, 1 if invalid (with a single-line reason on stderr).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"schema invalid: {msg}", file=sys.stderr)
    return 1


def validate(d: dict) -> int:
    required_top = {"host", "macos", "arch", "summary", "results"}
    missing = required_top - d.keys()
    if missing:
        return fail(f"missing top-level keys: {sorted(missing)}")

    for k in ("host", "macos", "arch"):
        if not isinstance(d[k], str):
            return fail(f"{k!r} must be string, got {type(d[k]).__name__}")

    s = d["summary"]
    if not isinstance(s, dict):
        return fail("summary must be object")
    for k in ("pass", "warn", "fail", "skip"):
        if k not in s:
            return fail(f"summary missing {k!r}")
        if not isinstance(s[k], int) or isinstance(s[k], bool) or s[k] < 0:
            return fail(f"summary.{k} must be non-negative int, got {s[k]!r}")

    r = d["results"]
    if not isinstance(r, list):
        return fail("results must be list")
    total = s["pass"] + s["warn"] + s["fail"] + s["skip"]
    if total != len(r):
        return fail(f"counter mismatch: summary sum={total} but len(results)={len(r)}")

    seen_ids: set[str] = set()
    for i, row in enumerate(r):
        if not isinstance(row, dict):
            return fail(f"results[{i}] must be object")
        for k in ("id", "status", "label", "hint"):
            if k not in row:
                return fail(f"results[{i}] missing {k!r}")
            if not isinstance(row[k], str):
                return fail(f"results[{i}].{k} must be string")
        if not row["id"]:
            return fail(f"results[{i}].id must be non-empty")
        if row["id"] in seen_ids:
            return fail(f"duplicate id within run: {row['id']!r}")
        seen_ids.add(row["id"])
        if row["status"] not in ("pass", "warn", "fail", "skip"):
            return fail(f"results[{i}].status invalid: {row['status']!r}")

    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_schema.py <posture.json>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        d = json.load(path.open())
    except Exception as e:
        return fail(f"could not parse {path}: {e}")
    return validate(d)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

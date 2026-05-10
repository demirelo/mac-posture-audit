#!/usr/bin/env bats

load '../helpers'

@test "--json --quick --redact emits valid JSON with counter parity" {
  run bash -c '"$1" --json --quick --redact 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"

  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  printf '%s\n' "$output" >"$BATS_TEST_TMPDIR/posture.json"
  python3 - "$BATS_TEST_TMPDIR/posture.json" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
s = d["summary"]
assert s["pass"] + s["warn"] + s["fail"] + s["skip"] == len(d["results"]), (s, len(d["results"]))
assert d["host"] == "<HOST>", d["host"]
assert all(r["status"] in ("pass", "warn", "fail", "skip") for r in d["results"])
assert all({"status", "label", "hint"} <= set(r) for r in d["results"])
PY
}

@test "--quick skips sudo-required Remote Login check" {
  run bash -c '"$1" --json --quick 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"

  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  printf '%s\n' "$output" >"$BATS_TEST_TMPDIR/posture.json"
  python3 - "$BATS_TEST_TMPDIR/posture.json" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
assert any(
    r["status"] == "skip" and "Remote Login state (requires sudo)" in r["label"]
    for r in d["results"]
), "missing quick-mode Remote Login skip"
PY
}

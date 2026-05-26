#!/usr/bin/env bats

load '../helpers'

# v1.3 decision layer — real-run JSON contract: summary.total, the top-level
# executive_verdict object, the ranked top_risks array, and --top 0 semantics.
# Additive fields per docs/schema.md; the schema validator tolerates them.

@test "--json surfaces executive_verdict, ranked top_risks, and summary.total" {
  run bash -c '"$1" --json --quick --redact --profile founder 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  printf '%s\n' "$output" >"$BATS_TEST_TMPDIR/posture.json"
  python3 - "$BATS_TEST_TMPDIR/posture.json" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
s = d["summary"]
assert s["total"] == len(d["results"]) == s["pass"] + s["warn"] + s["fail"] + s["skip"], s

ev = d["executive_verdict"]
assert ev["profile"] == "founder", ev
assert ev["tier"] in ("urgent", "high", "medium", "low", "none"), ev
assert isinstance(ev["text"], str) and ev["text"], ev
assert set(ev["top_counts"]) == {"urgent", "high", "medium", "low"}, ev["top_counts"]

tr = d["top_risks"]
assert isinstance(tr, list) and len(tr) <= 7, tr
assert [x["rank"] for x in tr] == list(range(1, len(tr) + 1)), tr
order = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
prios = [order[x["tier"]] for x in tr]
assert prios == sorted(prios), prios
for x in tr:
    assert {"rank", "id", "status", "tier", "label", "hint"} <= set(x), x
    assert x["status"] in ("warn", "fail"), x
PY
}

@test "--top 0 emits an empty top_risks array but keeps the verdict" {
  run bash -c '"$1" --json --quick --top 0 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  printf '%s\n' "$output" >"$BATS_TEST_TMPDIR/posture.json"
  python3 - "$BATS_TEST_TMPDIR/posture.json" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
assert d["top_risks"] == [], d["top_risks"]
assert d["executive_verdict"]["tier"], d.get("executive_verdict")
PY
}

@test "--explain prints a check rationale and exits without scanning" {
  run bash -c '"$1" --explain chain.fake_interview 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"chain.fake_interview"* ]]
  [[ "$output" == *"Contagious-Interview"* ]]
  [[ "$output" == *"web3 / founder: fail"* ]]
  # No scan happened — no section banners, no verdict.
  [[ "$output" != *"Executive Verdict"* ]]
  [[ "$output" != *"System Integrity"* ]]
}

@test "--explain unknown id points at AGENTS.md" {
  run bash -c '"$1" --explain bogus.nonexistent 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"No extended explanation"* ]]
  [[ "$output" == *"docs/AGENTS.md"* ]]
}

@test "--explain with no id errors" {
  run bash -c '"$1" --explain 2>&1' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--explain requires a check id"* ]]
}

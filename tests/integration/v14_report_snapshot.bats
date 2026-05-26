#!/usr/bin/env bats

load '../helpers'

# v1.4 — shareable & longitudinal: --report md, --snapshot, --trend.
# Snapshot/trend use a hermetic MSA_HISTORY_DIR under BATS_TEST_TMPDIR so they
# never touch the real ~/.mac-posture-audit/history.

@test "--report md renders markdown: verdict, action priority, top risks, results table" {
  run bash -c '"$1" --report md --quick --redact 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  [[ "$output" == *"# macOS Posture Audit"* ]]
  [[ "$output" == *"## Executive Verdict"* ]]
  [[ "$output" == *"**Action priority:"* ]]
  [[ "$output" == *"## Top risks to address"* ]]
  [[ "$output" == *"## All checks"* ]]
  # --redact must hold in the report too.
  [[ "$output" == *'`<HOST>`'* ]]
}

@test "--report rejects an unknown format" {
  run bash -c '"$1" --report xml 2>&1' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--report supports: md"* ]]
}

@test "--snapshot writes a redacted JSON to the history dir (implies --redact)" {
  local hist="$BATS_TEST_TMPDIR/history"
  run bash -c 'MSA_HISTORY_DIR="$2" "$1" --snapshot --quick 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh" "$hist"
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  local f
  f=$(ls "$hist"/posture-*.json 2>/dev/null | head -1)
  [ -n "$f" ]
  python3 - "$f" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
assert d["host"] == "<HOST>", d["host"]
assert "top_risks" in d and "executive_verdict" in d, sorted(d)
assert d["summary"]["total"] == len(d["results"]), (d["summary"], len(d["results"]))
PY
}

@test "--trend reports improved and regressed checks across snapshots" {
  local hist="$BATS_TEST_TMPDIR/history"
  mkdir -p "$hist"
  cat >"$hist/posture-20260101-000000.json" <<'JSON'
{"host":"<HOST>","macos":"26","arch":"arm64","summary":{"pass":0,"warn":1,"fail":1,"skip":0,"total":2},"executive_verdict":{},"top_risks":[],"results":[{"id":"ext.wallet","status":"warn","label":"w","hint":""},{"id":"ssh.keys.unencrypted","status":"fail","label":"k","hint":""}]}
JSON
  cat >"$hist/posture-20260201-000000.json" <<'JSON'
{"host":"<HOST>","macos":"26","arch":"arm64","summary":{"pass":1,"warn":0,"fail":1,"skip":0,"total":2},"executive_verdict":{},"top_risks":[],"results":[{"id":"ext.wallet","status":"fail","label":"w","hint":""},{"id":"ssh.keys.unencrypted","status":"pass","label":"k","hint":""}]}
JSON
  run bash -c 'MSA_HISTORY_DIR="$2" "$1" --trend 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh" "$hist"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Improved: 1"* ]]
  [[ "$output" == *"Regressed: 1"* ]]
  [[ "$output" == *"ext.wallet: warn -> fail"* ]]
  [[ "$output" == *"ssh.keys.unencrypted: fail -> pass"* ]]
}

@test "--trend with no history is graceful (no scan, exit 0)" {
  local hist="$BATS_TEST_TMPDIR/empty-history"
  run bash -c 'MSA_HISTORY_DIR="$2" "$1" --trend 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh" "$hist"
  [ "$status" -eq 0 ]
  [[ "$output" == *"No snapshot history"* ]]
}

@test "tools/render_report.py turns a posture JSON into self-contained HTML" {
  run bash -c '"$1" --json --quick --redact 2>/dev/null | python3 "$2"' _ \
    "$REPO_ROOT/mac-posture-audit.sh" "$REPO_ROOT/tools/render_report.py"
  [ "$status" -eq 0 ]
  [[ "$output" == *"<h1>macOS Posture Audit</h1>"* ]]
  [[ "$output" == *"Action priority:"* ]]
  [[ "$output" == *"Top risks to address"* ]]
  [[ "$output" == *"All checks"* ]]
  # Self-contained: no external stylesheet/script/image references.
  ! grep -qE '(src|href)=' <<<"$output"
}

@test "tools/render_report.py rejects non-posture JSON" {
  run bash -c 'printf "%s" "{\"x\":1}" | python3 "$1"' _ "$REPO_ROOT/tools/render_report.py"
  [ "$status" -eq 2 ]
}

@test "--trend with a single snapshot asks for at least two" {
  local hist="$BATS_TEST_TMPDIR/one"
  mkdir -p "$hist"
  cat >"$hist/posture-20260101-000000.json" <<'JSON'
{"host":"<HOST>","macos":"26","arch":"arm64","summary":{"pass":1,"warn":0,"fail":0,"skip":0,"total":1},"executive_verdict":{},"top_risks":[],"results":[{"id":"system.sip.enabled","status":"pass","label":"s","hint":""}]}
JSON
  run bash -c 'MSA_HISTORY_DIR="$2" "$1" --trend 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh" "$hist"
  [ "$status" -eq 0 ]
  [[ "$output" == *"at least 2 snapshots"* ]]
}

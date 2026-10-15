#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  mkdir -p "$MSA_HISTORY_DIR"
}

@test "trend fails closed on invalid oldest and newest snapshots" {
  local first="$MSA_HISTORY_DIR/posture-20260101-000000.json"
  local last="$MSA_HISTORY_DIR/posture-20260201-000000.json"
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"pass"}]}' >"$first"
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"fail",}]}' >"$last"
  run run_trend
  [ "$status" -eq 2 ]
  [[ "$output" != *'No status changes'* ]]
  [[ "$output" != *'Improved:'* ]]

  printf '%s\n' 'not json' >"$first"
  printf '%s\n' '{"results":[]}' >"$last"
  run run_trend
  [ "$status" -eq 2 ]
  [[ "$output" != *'No status changes'* ]]
}

@test "trend reports coverage changes added and removed results separately" {
  cat >"$MSA_HISTORY_DIR/posture-20260101-000000.json" <<'JSON'
{"results":[{"id":"fixture.unknown","status":"fail"},{"id":"fixture.known","status":"skip"},{"id":"fixture.removed","status":"fail"},{"id":"fixture.improved","status":"warn"},{"id":"fixture.regressed","status":"pass"}]}
JSON
  cat >"$MSA_HISTORY_DIR/posture-20260201-000000.json" <<'JSON'
{"results":[{"id":"fixture.unknown","status":"skip"},{"id":"fixture.known","status":"pass"},{"id":"fixture.added","status":"fail"},{"id":"fixture.improved","status":"pass"},{"id":"fixture.regressed","status":"fail"}]}
JSON
  run run_trend
  [ "$status" -eq 0 ]
  [[ "$output" == *'Improved: 1   Regressed: 1   Coverage changes: 2   Added: 1   Removed: 1'* ]]
  [[ "$output" == *'coverage   fixture.unknown: fail -> skip'* ]]
  [[ "$output" == *'removed    fixture.removed: was fail'* ]]
}

@test "trend preserves spaces and newlines in history paths and ignores snapshot symlinks" {
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history with spaces"$'\n'"and newline"
  mkdir -p "$MSA_HISTORY_DIR"
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"warn"}]}' >"$MSA_HISTORY_DIR/posture-20260101-000000.json"
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"pass"}]}' >"$MSA_HISTORY_DIR/posture-20260201-000000.json"
  printf '%s\n' 'invalid symlink target' >"$BATS_TEST_TMPDIR/unrelated.json"
  ln -s "$BATS_TEST_TMPDIR/unrelated.json" "$MSA_HISTORY_DIR/posture-20990101-000000.json"
  run run_trend
  [ "$status" -eq 0 ]
  [[ "$output" == *'2 snapshots'* ]]
  [[ "$output" == *'Improved: 1'* ]]
  [[ "$output" == *'history with spaces\nand newline'* ]]
}

@test "trend with valid matching reports states no changes" {
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"pass"}]}' >"$MSA_HISTORY_DIR/posture-20260101-000000.json"
  printf '%s\n' '{"results":[{"status":"pass","id":"fixture.id"}],"host":"fixture"}' >"$MSA_HISTORY_DIR/posture-20260201-000000.json"
  run run_trend
  [ "$status" -eq 0 ]
  [[ "$output" == *'No status changes'* ]]
}

#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  PREV="$BATS_TEST_TMPDIR/prev.json"
  CUR="$BATS_TEST_TMPDIR/current.json"
}

write_prev() {
  cat >"$PREV" <<'JSON'
{
  "host":"<HOST>","macos":"26.4.1","arch":"arm64",
  "summary":{"pass":2,"warn":1,"fail":0,"skip":0},
  "results":[
    {"id":"system.sip.enabled","status":"pass","label":"SIP","hint":""},
    {"id":"system.gatekeeper.enabled","status":"pass","label":"Gatekeeper","hint":""},
    {"id":"network.bluetooth.off","status":"warn","label":"BT on","hint":""}
  ]
}
JSON
}

build_current_helpers() {
  load_script
  reset_state
  MODE="json"
}

@test "--diff prints 'no posture changes' when current matches previous exactly" {
  write_prev
  build_current_helpers
  pass "SIP" "system.sip.enabled"
  pass "Gatekeeper" "system.gatekeeper.enabled"
  warn "BT on" "" "network.bluetooth.off"
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 0 ]
  [[ "$output" =~ "no posture changes" ]]
}

@test "--diff reports status flip" {
  write_prev
  build_current_helpers
  pass "SIP" "system.sip.enabled"
  pass "Gatekeeper" "system.gatekeeper.enabled"
  pass "BT off now" "network.bluetooth.off"
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 1 ]
  [[ "$output" =~ "network.bluetooth.off" ]]
  [[ "$output" =~ "warn -> pass" ]]
}

@test "--diff reports new and removed checks" {
  write_prev
  build_current_helpers
  pass "SIP" "system.sip.enabled"
  pass "BT off" "network.bluetooth.off"
  pass "FV" "system.filevault.on"
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 1 ]
  [[ "$output" =~ "(new)" ]] && [[ "$output" =~ "system.filevault.on" ]]
  [[ "$output" =~ "(removed)" ]] && [[ "$output" =~ "system.gatekeeper.enabled" ]]
}

@test "--diff against unparsable JSON exits 2" {
  echo "not json" >"$PREV"
  build_current_helpers
  pass "SIP" "system.sip.enabled"
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 2 ]
}

@test "--diff with missing file exits 2 in parse_args" {
  run "$REPO_ROOT/mac-posture-audit.sh" --diff "$BATS_TEST_TMPDIR/does-not-exist.json"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "cannot read" ]]
}

@test "--diff= with empty value exits 2" {
  run "$REPO_ROOT/mac-posture-audit.sh" --diff=
  [ "$status" -eq 2 ]
  [[ "$output" =~ "--diff requires a path" ]]
}

@test "--diff with empty separate value exits 2" {
  run "$REPO_ROOT/mac-posture-audit.sh" --diff ""
  [ "$status" -eq 2 ]
  [[ "$output" =~ "--diff requires a path" ]]
}

@test "--diff against schema-invalid previous JSON exits 2 without traceback" {
  cat >"$PREV" <<'JSON'
{"results":[{"status":"pass"}]}
JSON
  build_current_helpers
  pass "SIP" "system.sip.enabled"
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 2 ]
  [[ "$output" =~ "previous results[0].id" ]]
  [[ ! "$output" =~ "Traceback" ]]
}

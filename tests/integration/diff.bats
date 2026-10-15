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

@test "diff parser accepts reordered members and ignores row-shaped nested metadata" {
  build_current_helpers
  cat >"$PREV" <<'JSON'
{"results":[{"status":"warn","metadata":{"id":"fake.id","status":"pass"},"label":"braces },{ and escaped \"status\":\"pass\"","id":"system.sip.enabled"}],"summary":{"warn":1},"host":"fixture"}
JSON
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 0 ]
  [ "$output" = 'system.sip.enabled warn' ]
}

@test "diff parser decodes escaped object keys and result values" {
  build_current_helpers
  cat >"$PREV" <<'JSON'
{"res\u0075lts":[{"\u0069d":"system.sip.\u0065nabled","status":"p\u0061ss","label":"emoji \uD83D\uDD12"}]}
JSON
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 0 ]
  [ "$output" = 'system.sip.enabled pass' ]
}

@test "diff parser rejects malformed JSON without returning partial rows" {
  build_current_helpers
  local document
  for document in \
    '{"results":[{"id":"fixture.id","status":"pass",}]}' \
    '{"results":[{"id":"fixture.id","status":"pass"},]}' \
    '{"results":[{"id":"fixture.id","status":"pass"}]}GARBAGE' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":01}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":NaN}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":"\q"}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":"\uD800"}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":"\uDC00"}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":"unterminated}' \
    '{"results":[{"id":"fixture.id","status":"pass"}],"x":truefalse}' \
    '{"nested":{"results":[]}}'; do
    printf '%s\n' "$document" >"$PREV"
    run _diff_parse_rows fixture <"$PREV"
    [ "$status" -eq 2 ]
    [[ "$output" != *'fixture.id pass'* ]]
  done
}

@test "diff parser rejects ambiguous keys and duplicate IDs including escaped aliases" {
  build_current_helpers
  local document
  for document in \
    '{"results":[],"results":[]}' \
    '{"results":[{"id":"fixture.id","status":"pass","status":"fail"}]}' \
    '{"results":[{"id":"fixture.id","status":"pass"},{"id":"fixture.\u0069d","status":"fail"}]}' \
    '{"results":[{"id":"fixture.id","\u0069d":"other.id","status":"pass"}]}'; do
    printf '%s\n' "$document" >"$PREV"
    run _diff_parse_rows fixture <"$PREV"
    [ "$status" -eq 2 ]
    [[ "$output" == *'duplicate'* ]]
  done
}

@test "diff parser rejects bad row types and identifier control injection" {
  build_current_helpers
  local document
  for document in \
    '{"results":{}}' \
    '{"results":[null]}' \
    '{"results":[{"id":12,"status":"pass"}]}' \
    '{"results":[{"id":"fixture.id","status":true}]}' \
    '{"results":[{"id":"fixture.id","status":"unknown"}]}' \
    '{"results":[{"id":"fixture id","status":"pass"}]}' \
    '{"results":[{"id":"fixture\u0000id","status":"pass"}]}' \
    '{"results":[{"id":"fixture\nid","status":"pass"}]}' \
    '{"results":[{"id":"fixture\u001bid","status":"pass"}]}'; do
    printf '%s\n' "$document" >"$PREV"
    run _diff_parse_rows fixture <"$PREV"
    [ "$status" -eq 2 ]
  done
}

@test "diff parser rejects invalid UTF-8 and accepts raw UTF-8 strings" {
  build_current_helpers
  printf '{"results":[],"label":"\377"}\n' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 2 ]
  [[ "$output" == *'invalid UTF-8'* ]]

  printf '{"results":[],"label":"\300\257"}\n' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 2 ]

  printf '%s\n' '{"results":[{"id":"fixture.id","status":"pass","label":"résumé 🔒"}]}' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 0 ]
  [ "$output" = 'fixture.id pass' ]
}

@test "diff parser bounds document size nesting and result count" {
  build_current_helpers
  awk 'BEGIN { printf "{\"results\":[],\"nested\":"; for (i=0;i<70;i++) printf "["; printf "0"; for (i=0;i<70;i++) printf "]"; print "}" }' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 2 ]
  [[ "$output" == *'nesting limit'* ]]

  awk 'BEGIN { printf "{\"results\":[],\"label\":\""; for(i=0;i<8193;i++) printf "%01024d", 0; print "\"}" }' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 2 ]
  [[ "$output" == *'input limit'* ]]

  awk 'BEGIN { printf "{\"results\":["; for (i=0;i<10001;i++) printf "%s{\"id\":\"fixture.%d\",\"status\":\"pass\"}", i ? "," : "", i; print "]}" }' >"$PREV"
  run _diff_parse_rows fixture <"$PREV"
  [ "$status" -eq 2 ]
  [[ "$output" == *'result limit'* ]]
}

@test "diff does not mark failed-to-skipped probes as improvements" {
  build_current_helpers
  printf '%s\n' '{"results":[{"id":"fixture.id","status":"fail"}]}' >"$PREV"
  skip 'Probe unavailable' '' 'fixture.id'
  DIFF_PATH="$PREV"
  run emit_diff
  [ "$status" -eq 1 ]
  [[ "$output" == '? fixture.id'* ]]
  [[ "$output" == *'fail -> skip'* ]]
}

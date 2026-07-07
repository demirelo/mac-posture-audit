#!/usr/bin/env bats

# v1.7 — structured `evidence` fields on JSON rows.
#
# A check stages evidence via `ev` / `ev_raw` immediately before the
# pass/warn/fail/skip call; _record consumes-and-clears it into ROW_EVIDENCE,
# and _build_json_document emits it as an `evidence` object. The feature is
# additive: rows that stage nothing are byte-identical to pre-v1.7 output.

load '../helpers.bash'

setup() {
  load_script
  MODE="json"
}

@test "ev/ev_raw attach a well-typed evidence object to the next row only" {
  ev probe "csrutil status"
  ev_raw enabled false
  fail "SIP is disabled" "csrutil enable" "system.sip.enabled"
  # The very next row stages nothing — it must carry NO evidence key.
  pass "Gatekeeper is enabled" "system.gatekeeper.enabled"

  doc=$(_build_json_document)
  python3 - "$doc" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
rows = {r["id"]: r for r in d["results"]}
sip = rows["system.sip.enabled"]
assert sip["evidence"] == {"probe": "csrutil status", "enabled": False}, sip
# ev_raw false must be a JSON boolean, not the string "false".
assert sip["evidence"]["enabled"] is False, sip["evidence"]
# The row that staged nothing has no evidence key (back-compat).
assert "evidence" not in rows["system.gatekeeper.enabled"], rows["system.gatekeeper.enabled"]
PY
}

@test "ev_raw emits integers and booleans unquoted; ev escapes strings" {
  ev_raw managers_running_scripts 2
  ev_raw scanner_present false
  ev note $'a "quoted"\tvalue'
  pass "supply ok" "supply.posture"

  doc=$(_build_json_document)
  python3 - "$doc" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
e = {r["id"]: r for r in d["results"]}["supply.posture"]["evidence"]
assert e["managers_running_scripts"] == 2 and isinstance(e["managers_running_scripts"], int), e
assert e["scanner_present"] is False, e
assert e["note"] == 'a "quoted"\tvalue', e["note"]
PY
}

@test "staged evidence is cleared after each row — never leaks to a later row" {
  ev_raw only_here true
  pass "first" "first.row"
  # _EV must be empty now; the next record must not inherit only_here.
  [ -z "$_EV" ]
  pass "second" "second.row"

  doc=$(_build_json_document)
  python3 - "$doc" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
rows = {r["id"]: r for r in d["results"]}
assert rows["first.row"]["evidence"] == {"only_here": True}, rows["first.row"]
assert "evidence" not in rows["second.row"], rows["second.row"]
PY
}

@test "the full document still parses and passes the schema validator with evidence present" {
  ev probe "csrutil status"; ev_raw enabled false
  fail "SIP is disabled" "csrutil enable" "system.sip.enabled"
  ev_raw time_machine false; ev_raw offsite false; ev_raw icloud_drive true
  warn "backup partial" "add a second source" "backup.recovery_path"
  pass "no evidence row" "system.gatekeeper.enabled"

  _build_json_document >"$BATS_TEST_TMPDIR/posture.json"
  run python3 "$REPO_ROOT/tests/lib/validate_schema.py" "$BATS_TEST_TMPDIR/posture.json"
  [ "$status" -eq 0 ]
}

@test "evidence-bearing rows survive the --diff parser (id/status still extracted)" {
  ev_raw managers_running_scripts 2; ev_raw scanner_present false
  fail "supply gap" "fix it" "supply.posture"
  pass "clean" "system.sip.enabled"

  _build_json_document >"$BATS_TEST_TMPDIR/cur.json"
  # Reuse the script's own stock-shell diff parser on the evidence-bearing doc.
  run bash -c 'source "$1"; _diff_parse_rows current < "$2"' _ \
    "$REPO_ROOT/mac-posture-audit.sh" "$BATS_TEST_TMPDIR/cur.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"supply.posture fail"* ]]
  [[ "$output" == *"system.sip.enabled pass"* ]]
}

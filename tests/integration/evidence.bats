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

@test "recognized integrity states attach verified booleans and FileVault enums" {
  local enabled state fixture
  for enabled in true false; do
    reset_state
    if $enabled; then state=on; fixture=enabled; else state=off; fixture=disabled; fi
    mock_cli csrutil "csrutil/$fixture.txt"
    mock_cli spctl "spctl/$fixture.txt"
    mock_cli fdesetup "fdesetup/$state.txt"
    section_01_system_integrity
    python3 - "$(_build_json_document)" "$enabled" "$state" <<'PY'
import json, sys
rows = {row['id']: row for row in json.loads(sys.argv[1])['results']}
for ident, probe in [('system.sip.enabled', 'csrutil status'), ('system.gatekeeper.enabled', 'spctl --status')]:
    assert rows[ident]['evidence'] == {'probe': probe, 'enabled': sys.argv[2] == 'true'}, rows[ident]
assert rows['system.filevault.on']['evidence'] == {'probe': 'fdesetup status', 'state': sys.argv[3]}
PY
  done
}

@test "failed or unrecognized integrity probes do not attach a false enabled boolean" {
  local mode
  for mode in failure unknown; do
    reset_state
    if [[ "$mode" == failure ]]; then
      mock_cli csrutil csrutil/enabled.txt 1
      mock_cli spctl spctl/enabled.txt 1
      mock_cli fdesetup fdesetup/on.txt 1
    else
      mock_cli_script csrutil $'#!/bin/bash\nprintf "Custom Configuration\\n"'
      mock_cli_script spctl $'#!/bin/bash\nprintf "unsupported output\\n"'
      mock_cli_script fdesetup $'#!/bin/bash\nprintf "unsupported output\\n"'
    fi
    section_01_system_integrity
    python3 - "$(_build_json_document)" <<'PY'
import json, sys
rows = {row['id']: row for row in json.loads(sys.argv[1])['results']}
for ident in ['system.sip.enabled', 'system.gatekeeper.enabled', 'system.filevault.on']:
    row = rows[ident]
    assert row['status'] == 'skip', row
    assert row['evidence']['state'] == 'unknown', row
    assert 'enabled' not in row['evidence'], row
PY
  done
}

@test "partial supply evidence identifies known gaps without claiming effective policy" {
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  unset NPM_CONFIG_USERCONFIG
  _tool_path() { case "$1" in npm | yarn | pnpm) return 0 ;; *) return 1 ;; esac; }
  command() { return 1; }
  _check_supply_direnv() { :; }
  _check_supply_pip_extra_index() { :; }
  _check_supply_uv_config() { :; }
  printf 'ignore-scripts=false\n' >"$HOME/.npmrc"
  printf 'enableScripts: ${DYNAMIC_POLICY}\n' >"$HOME/.yarnrc.yml"
  section_13_supply_chain
  python3 - "$(_build_json_document)" <<'PY'
import json, sys
rows = {row['id']: row for row in json.loads(sys.argv[1])['results']}
row = rows['supply.posture']
assert row['status'] == 'fail', row
assert row['evidence'] == {
    'managers_running_scripts': 2,
    'policy_scope': 'user_config',
    'policy_unknown': True,
    'effective_policy_verified': False,
    'scanner_present': False,
}, row
PY
}

@test "zero known supply gaps still carry unknown scope when policy is unreadable" {
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  unset NPM_CONFIG_USERCONFIG
  _tool_path() { case "$1" in npm | yarn | pnpm | socket) return 0 ;; *) return 1 ;; esac; }
  command() { return 1; }
  _check_supply_direnv() { :; }
  _check_supply_pip_extra_index() { :; }
  _check_supply_uv_config() { :; }
  section_13_supply_chain
  python3 - "$(_build_json_document)" <<'PY'
import json, sys
row = next(row for row in json.loads(sys.argv[1])['results'] if row['id'] == 'supply.posture')
assert row['status'] == 'skip', row
assert row['evidence'] == {
    'managers_running_scripts': 0,
    'policy_scope': 'user_config',
    'policy_unknown': True,
    'effective_policy_verified': False,
    'scanner_present': True,
}, row
PY
}

@test "mixed encrypted and unclassified SSH keys emit unknown evidence" {
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/.ssh"
  : >"$HOME/.ssh/id_ed25519"
  : >"$HOME/.ssh/id_rsa"
  mock_cli_script ssh-keygen '#!/bin/bash
case "$*" in
  *id_rsa*) echo "incorrect passphrase supplied to decrypt private key" >&2 ;;
  *) echo "invalid format" >&2 ;;
esac
exit 255'
  export SSH_AUTH_SOCK="$HOME/secretive-agent.sock"
  section_11_ssh
  python3 - "$(_build_json_document)" <<'PY'
import json, sys
row = next(row for row in json.loads(sys.argv[1])['results'] if row['id'] == 'ssh.posture')
assert row['status'] == 'skip', row
assert row['evidence'] == {'key_state': 'unknown', 'external_agent': True}, row
PY
}

#!/usr/bin/env bats

load '../helpers'

setup() {
  load_script
}

@test "JSON escapes every representable C0 control byte" {
  local i ch value=""
  for ((i = 1; i < 32; i++)); do
    printf -v ch '%03o' "$i"
    printf -v ch '%b' "\\$ch"
    value+="$ch"
  done
  local escaped
  escaped=$(_json_escape "$value")
  python3 - "$escaped" <<'PY'
import json, sys
assert json.loads('"' + sys.argv[1] + '"') == ''.join(map(chr, range(1, 32)))
PY
}

@test "terminal findings cannot inject ANSI sequences or extra lines" {
  MODE=full
  run warn $'evil\033[2J\rFORGED\nPASS' $'hint\033]52;c;AAAA\a' test.output
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\033'* ]]
  [[ "$output" != *$'\r'* ]]
  [[ "$output" != *$'\a'* ]]
  [[ "$output" == *'\u001b'* ]]
  [[ "$output" == *'\nPASS'* ]]
}

@test "Markdown treats host and findings as text and includes remediation" {
  warn '<img src="https://tracker.invalid/pixel"> [click](https://evil.invalid)' 'Review this setting' test.output
  run emit_markdown_report
  [ "$status" -eq 0 ]
  [[ "$output" != *'<img '* ]]
  [[ "$output" != *'[click](https://evil.invalid)'* ]]
  [[ "$output" == *'Review this setting'* ]]
}

@test "hidden top risks do not claim that warnings are absent" {
  TOP_N=0
  warn 'Unsafe setting' 'Fix it' test.output
  run emit_markdown_report
  [[ "$output" != *'No warnings or failures'* ]]
  [[ "$output" == *'hidden'* ]]
}

@test "snapshots are private and never overwrite a same-second snapshot" {
  SNAPSHOT=true
  REDACT=true
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  pass 'Safe' test.output
  (umask 022; maybe_write_snapshot; maybe_write_snapshot)
  local files=("$MSA_HISTORY_DIR"/posture-*.json)
  [ "${#files[@]}" -eq 2 ]
  [ "$(stat -f '%Lp' "$MSA_HISTORY_DIR")" = 700 ]
  [ "$(stat -f '%Lp' "${files[0]}")" = 600 ]
}

@test "snapshots reject a symlink directory without writing through it" {
  SNAPSHOT=true
  REDACT=true
  mkdir -p "$BATS_TEST_TMPDIR/target"
  ln -s "$BATS_TEST_TMPDIR/target" "$BATS_TEST_TMPDIR/history"
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  run maybe_write_snapshot
  [ "$status" -eq 2 ]
  [ -z "$(ls -A "$BATS_TEST_TMPDIR/target")" ]
}

@test "snapshots reject an existing directory accessible to other users" {
  SNAPSHOT=true
  REDACT=true
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  mkdir -m 755 "$MSA_HISTORY_DIR"
  run maybe_write_snapshot
  [ "$status" -eq 2 ]
  [ -z "$(ls -A "$MSA_HISTORY_DIR")" ]
}

@test "snapshot failure is a script error even when findings pass" {
  SNAPSHOT=true
  REDACT=true
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/not-a-directory"
  printf keep >"$MSA_HISTORY_DIR"
  pass 'Safe' test.output
  run emit_summary
  [ "$status" -eq 2 ]
  [ "$(cat "$MSA_HISTORY_DIR")" = keep ]
}

@test "top count rejects missing and excessive values and accepts decimal zero padding" {
  run "$REPO_ROOT/mac-posture-audit.sh" --top
  [ "$status" -eq 2 ]
  run "$REPO_ROOT/mac-posture-audit.sh" --top=999999999999999999999999
  [ "$status" -eq 2 ]
  parse_args --top=008
  [ "$TOP_N" = 8 ]
}

@test "snapshot refuses a directory whose ACL bypasses mode permissions" {
  SNAPSHOT=true
  REDACT=true
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  mkdir -m 700 "$MSA_HISTORY_DIR"
  /bin/chmod +a 'everyone allow list,search,file_inherit,directory_inherit' "$MSA_HISTORY_DIR"
  run maybe_write_snapshot
  [ "$status" -eq 2 ]
  [ -z "$(ls -A "$MSA_HISTORY_DIR")" ]
}

@test "direct execution ignores BASH_ENV and project PATH wrappers" {
  local marker="$BATS_TEST_TMPDIR/executed"
  printf 'printf unsafe > %q\n' "$marker" >"$BATS_TEST_TMPDIR/startup"
  mock_cli_script sed "#!/bin/bash
printf unsafe > '$marker'
exit 1"
  run env BASH_ENV="$BATS_TEST_TMPDIR/startup" "$REPO_ROOT/mac-posture-audit.sh" --help
  [ "$status" -eq 0 ]
  [ ! -e "$marker" ]
}

@test "JSON report with no findings remains valid on Bash 3.2" {
  run _build_json_document
  [ "$status" -eq 0 ]
  python3 - "$output" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
assert data['results'] == []
assert data['summary']['total'] == 0
PY
}

@test "same-second snapshots retain comparison order and leave existing targets unchanged" {
  SNAPSHOT=true
  REDACT=true
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  mkdir -m 700 "$MSA_HISTORY_DIR"
  printf keep >"$BATS_TEST_TMPDIR/target"
  ln -s "$BATS_TEST_TMPDIR/target" "$MSA_HISTORY_DIR/posture-20261015-120000_0001.json"
  date() { printf '20261015-120000\n'; }
  warn 'Unsafe' 'Fix it' test.output
  maybe_write_snapshot
  reset_state
  SNAPSHOT=true
  REDACT=true
  pass 'Safe' test.output
  maybe_write_snapshot
  [ "$(cat "$BATS_TEST_TMPDIR/target")" = keep ]
  [ -f "$MSA_HISTORY_DIR/posture-20261015-120000_0002.json" ]
  [ -f "$MSA_HISTORY_DIR/posture-20261015-120000_0003.json" ]
  run run_trend
  [ "$status" -eq 0 ]
  [[ "$output" == *'Improved: 1'* ]]
}

@test "trend handles an existing empty history directory on Bash 3.2" {
  export MSA_HISTORY_DIR="$BATS_TEST_TMPDIR/history"
  mkdir -m 700 "$MSA_HISTORY_DIR"
  run run_trend
  [ "$status" -eq 0 ]
  [[ "$output" == *'found 0'* ]]
}

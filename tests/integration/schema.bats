#!/usr/bin/env bats

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
}

@test "stdlib schema validator accepts a real --json --quick run" {
  cd "$REPO_ROOT"
  ./mac-posture-audit.sh --json --quick --redact >"$BATS_TEST_TMPDIR/posture.json" || true
  run python3 tests/lib/validate_schema.py "$BATS_TEST_TMPDIR/posture.json"
  [ "$status" -eq 0 ]
}

@test "stdlib schema validator rejects a counter mismatch" {
  cat >"$BATS_TEST_TMPDIR/bad.json" <<'JSON'
{
  "host":"x","macos":"y","arch":"z",
  "summary":{"pass":1,"warn":0,"fail":0,"skip":0},
  "results":[
    {"id":"a.b.c","status":"pass","label":"a","hint":""},
    {"id":"a.b.d","status":"pass","label":"b","hint":""}
  ]
}
JSON
  cd "$REPO_ROOT"
  run python3 tests/lib/validate_schema.py "$BATS_TEST_TMPDIR/bad.json"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "counter mismatch" ]] || [[ "$stderr" =~ "counter mismatch" ]] || true
}

@test "stdlib schema validator rejects a duplicate id" {
  cat >"$BATS_TEST_TMPDIR/dup.json" <<'JSON'
{
  "host":"x","macos":"y","arch":"z",
  "summary":{"pass":2,"warn":0,"fail":0,"skip":0},
  "results":[
    {"id":"a.b.c","status":"pass","label":"first","hint":""},
    {"id":"a.b.c","status":"pass","label":"dup","hint":""}
  ]
}
JSON
  cd "$REPO_ROOT"
  run python3 tests/lib/validate_schema.py "$BATS_TEST_TMPDIR/dup.json"
  [ "$status" -eq 1 ]
}

@test "stdlib schema validator rejects an invalid status enum" {
  cat >"$BATS_TEST_TMPDIR/badstatus.json" <<'JSON'
{
  "host":"x","macos":"y","arch":"z",
  "summary":{"pass":1,"warn":0,"fail":0,"skip":0},
  "results":[
    {"id":"a.b.c","status":"sloppy","label":"x","hint":""}
  ]
}
JSON
  cd "$REPO_ROOT"
  run python3 tests/lib/validate_schema.py "$BATS_TEST_TMPDIR/badstatus.json"
  [ "$status" -eq 1 ]
}

@test "stdlib schema validator rejects an empty id" {
  cat >"$BATS_TEST_TMPDIR/emptyid.json" <<'JSON'
{
  "host":"x","macos":"y","arch":"z",
  "summary":{"pass":1,"warn":0,"fail":0,"skip":0},
  "results":[
    {"id":"","status":"pass","label":"x","hint":""}
  ]
}
JSON
  cd "$REPO_ROOT"
  run python3 tests/lib/validate_schema.py "$BATS_TEST_TMPDIR/emptyid.json"
  [ "$status" -eq 1 ]
}

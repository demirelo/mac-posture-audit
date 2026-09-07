#!/usr/bin/env bats

@test "mac-snapshot-append independent acceptance regressions" {
  run python3 "$BATS_TEST_DIRNAME/../audit/test_audit_snapshots.py"
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$output"
    return 1
  fi
}

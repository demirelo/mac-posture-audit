#!/usr/bin/env bats

@test "mac-ssh-config-syntax independent acceptance regressions" {
  run python3 "$BATS_TEST_DIRNAME/../audit/test_audit_ssh_config.py"
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$output"
    return 1
  fi
}

#!/usr/bin/env bats

load '../helpers'

@test "--version prints the script version" {
  run "$REPO_ROOT/mac-posture-audit.sh" --version

  [ "$status" -eq 0 ]
  # Read the canonical version directly from the script so this test
  # doesn't drift every time we bump. The format is `SCRIPT_VERSION="x.y.z"`.
  expected_version=$(grep -E '^SCRIPT_VERSION=' "$REPO_ROOT/mac-posture-audit.sh" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
  [ "$output" = "mac-posture-audit ${expected_version}" ]
}

@test "--help exits successfully and lists common flags" {
  run "$REPO_ROOT/mac-posture-audit.sh" --help

  [ "$status" -eq 0 ]
  [[ "$output" == *"--quick"* ]]
  [[ "$output" == *"--json"* ]]
  [[ "$output" == *"--version"* ]]
  [[ "$output" == *"--help"* ]]
}

@test "unknown argument exits with script-error status" {
  run "$REPO_ROOT/mac-posture-audit.sh" --definitely-not-a-flag

  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown arg"* ]]
}

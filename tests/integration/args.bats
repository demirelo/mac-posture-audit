#!/usr/bin/env bats

load '../helpers'

@test "--version prints the script version" {
  run "$REPO_ROOT/mac-posture-audit.sh" --version

  [ "$status" -eq 0 ]
  [ "$output" = "mac-posture-audit 0.1.0" ]
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

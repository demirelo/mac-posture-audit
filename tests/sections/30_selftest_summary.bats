#!/usr/bin/env bats

load '../helpers'

# Tests for the v1.2.0 housekeeping additions:
#   - run_selftest function (smoke-tests the catalog + record paths)
#   - _emit_summary_line one-line machine-parseable summary

@test "run_selftest exits 0 + prints 'selftest OK' when everything works" {
  load_script

  # run_selftest exits inside the function — wrap with run.
  run run_selftest
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"selftest OK"* ]]
}

@test "_emit_summary_line produces a stable token-stream" {
  load_script
  PASS_N=42
  WARN_N=3
  FAIL_N=1
  SKIP_N=7
  PROFILE="web3"

  run _emit_summary_line
  [[ "$status" -eq 0 ]]
  [[ "$output" == "mac-posture-audit summary version=$SCRIPT_VERSION profile=web3 pass=42 warn=3 fail=1 skip=7" ]]
}

@test "_emit_summary_line falls back to profile=normal when unset" {
  load_script
  PASS_N=1 WARN_N=0 FAIL_N=0 SKIP_N=0
  PROFILE=""

  run _emit_summary_line
  [[ "$output" == *"profile=normal"* ]]
}

@test "summary line reports SCRIPT_VERSION accurately" {
  load_script

  run _emit_summary_line
  [[ "$output" == *"version=$SCRIPT_VERSION"* ]]
}

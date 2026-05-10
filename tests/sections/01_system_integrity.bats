#!/usr/bin/env bats

load '../helpers'

@test "SIP, Gatekeeper, and FileVault pass when enabled" {
  load_script
  mock_cli csrutil csrutil/enabled.txt
  mock_cli spctl spctl/enabled.txt
  mock_cli fdesetup fdesetup/on.txt

  section_01_system_integrity

  assert_recorded pass "SIP (System Integrity Protection) is enabled"
  assert_recorded pass "Gatekeeper is enabled"
  assert_recorded pass "FileVault is on"
  assert_recorded skip "Apple Silicon boot security checks"
}

@test "SIP, Gatekeeper, and FileVault fail when disabled" {
  load_script
  mock_cli csrutil csrutil/disabled.txt
  mock_cli spctl spctl/disabled.txt
  mock_cli fdesetup fdesetup/off.txt

  section_01_system_integrity

  assert_recorded fail "SIP is disabled"
  assert_recorded fail "Gatekeeper is disabled"
  assert_recorded fail "FileVault is OFF"
}

@test "Apple Silicon secure boot records bputil posture" {
  load_script
  mock_cli csrutil csrutil/enabled.txt
  mock_cli spctl spctl/enabled.txt
  mock_cli fdesetup fdesetup/on.txt
  mock_cli bputil bputil/full_security.txt
  mock_cli_script sudo '#!/usr/bin/env bash
if [[ "$1" == "-n" ]]; then shift; fi
exec "$@"'
  IS_APPLE_SILICON=true

  section_01_system_integrity

  assert_recorded pass "Apple Silicon Secure Boot: Full Security"
  assert_recorded pass "Third-party kernel extensions disabled"
}

@test "quick mode skips bputil on Apple Silicon" {
  load_script
  mock_cli csrutil csrutil/enabled.txt
  mock_cli spctl spctl/enabled.txt
  mock_cli fdesetup fdesetup/on.txt
  IS_APPLE_SILICON=true
  QUICK=true

  section_01_system_integrity

  assert_recorded skip "bputil boot security check"
}

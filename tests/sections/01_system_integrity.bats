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

@test "failed integrity probes cannot report an enabled or disabled state" {
  load_script
  mock_cli csrutil csrutil/enabled.txt 1
  mock_cli spctl spctl/enabled.txt 1
  mock_cli fdesetup fdesetup/on.txt 1

  section_01_system_integrity

  [ "$(_status_of system.sip.enabled)" = skip ]
  [ "$(_status_of system.gatekeeper.enabled)" = skip ]
  [ "$(_status_of system.filevault.on)" = skip ]
}

@test "custom SIP configuration is not mistaken for fully enabled protection" {
  load_script
  mock_cli_script csrutil '#!/bin/bash
printf "System Integrity Protection status: unknown (Custom Configuration).\nFilesystem Protections: enabled\n"'
  mock_cli_script spctl '#!/bin/bash
echo "unexpected status output"'
  mock_cli_script fdesetup '#!/bin/bash
echo "status unavailable"'

  section_01_system_integrity

  [ "$(_status_of system.sip.enabled)" = skip ]
  [ "$(_status_of system.gatekeeper.enabled)" = skip ]
  [ "$(_status_of system.filevault.on)" = skip ]
}

@test "unrecognized boot policy output is skipped without false failures" {
  load_script
  mock_cli csrutil csrutil/enabled.txt
  mock_cli spctl spctl/enabled.txt
  mock_cli fdesetup fdesetup/on.txt
  mock_cli_script sudo '#!/bin/bash
echo "unsupported policy format"'
  IS_APPLE_SILICON=true

  section_01_system_integrity

  [ "$(_status_of boot.secure.full)" = skip ]
  [ "$(_status_of boot.kexts.disabled)" = skip ]
}

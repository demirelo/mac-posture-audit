#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
}

@test "normal profile: ext.wallet remains warn" {
  PROFILE="normal"
  warn "Wallet extension(s) installed: MetaMask" "..." "ext.wallet"
  assert_recorded warn "Wallet extension"
  [ "$WARN_N" -eq 1 ]
  [ "$FAIL_N" -eq 0 ]
}

@test "web3 profile: ext.wallet warn -> fail" {
  PROFILE="web3"
  warn "Wallet extension(s) installed: MetaMask" "..." "ext.wallet"
  assert_recorded fail "Wallet extension"
  [ "$WARN_N" -eq 0 ]
  [ "$FAIL_N" -eq 1 ]
}

@test "paranoid profile: bluetooth warn -> fail" {
  PROFILE="paranoid"
  warn "Bluetooth is on" "..." "network.bluetooth.off"
  assert_recorded fail "Bluetooth is on"
  [ "$FAIL_N" -eq 1 ]
}

@test "developer profile: supply.scanner warn -> fail" {
  PROFILE="developer"
  warn "No supply-chain scanner / age-cooldown mechanism detected" "..." "supply.scanner"
  assert_recorded fail "supply-chain scanner"
}

@test "profile override does not affect unmapped checks" {
  PROFILE="paranoid"
  warn "FileVault state unknown" "..." "system.filevault.on"
  assert_recorded warn "FileVault state unknown"
  [ "$WARN_N" -eq 1 ]
}

@test "profile override does not change a pass status to fail" {
  PROFILE="web3"
  pass "no wallet" "ext.wallet"
  assert_recorded pass "no wallet"
  [ "$PASS_N" -eq 1 ]
  [ "$FAIL_N" -eq 0 ]
}

@test "unknown profile rejected by parse_args" {
  run "$REPO_ROOT/mac-posture-audit.sh" --profile bogus
  [ "$status" -eq 2 ]
  [[ "$output" =~ "unknown profile" ]]
}

@test "--profile=web3 syntax accepted" {
  run "$REPO_ROOT/mac-posture-audit.sh" --profile=web3 --json --quick --redact
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  [[ "$output" =~ \"id\" ]]
}

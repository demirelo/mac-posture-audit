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

# ── v1.5: journalist profile ──────────────────────────────────────────────

@test "journalist profile: lockdown-off skip -> warn" {
  PROFILE="journalist"
  skip "Lockdown Mode is off" "" "privacy.lockdown.on"
  assert_recorded warn "Lockdown Mode is off"
  [ "$WARN_N" -eq 1 ]
}

@test "journalist profile: bluetooth warn -> fail" {
  PROFILE="journalist"
  warn "Bluetooth is on" "..." "network.bluetooth.off"
  assert_recorded fail "Bluetooth is on"
  [ "$FAIL_N" -eq 1 ]
}

@test "journalist profile: diagnostics telemetry warn -> fail" {
  PROFILE="journalist"
  warn "Diagnostics submission is on" "..." "privacy.diagnostics.off"
  assert_recorded fail "Diagnostics"
}

@test "journalist profile: leaves crypto/supply-chain at default (not its focus)" {
  PROFILE="journalist"
  warn "Wallet extension(s) installed: MetaMask" "..." "ext.wallet"
  assert_recorded warn "Wallet extension"
  [ "$FAIL_N" -eq 0 ]
}

# ── v1.5: --profile auto (advisory) ───────────────────────────────────────

@test "--profile auto recommends a profile and exits without scanning" {
  run bash -c '"$1" --profile auto 2>&1' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Recommended profile:"* ]]
  [[ "$output" != *"Summary"* ]]
  [[ "$output" != *"System Integrity"* ]]
}

@test "--profile journalist end-to-end reports under the journalist profile" {
  run bash -c '"$1" --quick --json --profile journalist 2>/dev/null' _ "$REPO_ROOT/mac-posture-audit.sh"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  [[ "$output" == *'"profile":"journalist"'* ]]
}

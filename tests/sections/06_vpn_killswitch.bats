#!/usr/bin/env bats

load '../helpers'

# Tests for the _check_vpn_killswitch helper that section_06_dns_outbound
# delegates to. Called directly to avoid having to mock out the rest of
# section 06's DNS / outbound monitor probes.

setup_killswitch_sandbox() {
  KS_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$KS_HOME"
  VPN_KILLSWITCH_ROOTS=("$KS_HOME")
  export VPN_KILLSWITCH_ROOTS
}

write_mullvad_settings() {
  local body="$1"
  local dir="$KS_HOME/Library/Application Support/Mullvad VPN"
  mkdir -p "$dir"
  printf '%s\n' "$body" >"$dir/settings.json"
}

make_protonvpn_present() {
  mkdir -p "$KS_HOME/Library/Application Support/ProtonVPN"
}

make_nordvpn_present() {
  mkdir -p "$KS_HOME/Library/Application Support/nordvpn-app"
}

@test "no VPN brand detected — skip with N/A" {
  load_script
  setup_killswitch_sandbox

  _check_vpn_killswitch

  assert_recorded skip "No supported VPN brand for killswitch verification"
}

@test "Mullvad with block_when_disconnected=true — passes" {
  load_script
  setup_killswitch_sandbox
  write_mullvad_settings '{
    "tunnel_options": {},
    "block_when_disconnected": true,
    "auto_connect": true
  }'

  _check_vpn_killswitch

  assert_recorded pass "VPN killswitch is ON"
  [[ "${RESULTS_PASS[*]}" == *"mullvad:on"* ]]
}

@test "Mullvad with block_when_disconnected=false — warns" {
  load_script
  setup_killswitch_sandbox
  write_mullvad_settings '{
    "block_when_disconnected": false
  }'

  _check_vpn_killswitch

  assert_recorded warn "VPN killswitch is OFF"
}

@test "Mullvad with block_when_disconnected=false — paranoid escalates to fail" {
  load_script
  setup_killswitch_sandbox
  PROFILE="paranoid"
  write_mullvad_settings '{
    "block_when_disconnected": false
  }'

  _check_vpn_killswitch

  assert_recorded fail "VPN killswitch is OFF"
}

@test "Mullvad with block_when_disconnected=false — web3 escalates to fail" {
  load_script
  setup_killswitch_sandbox
  PROFILE="web3"
  write_mullvad_settings '{
    "block_when_disconnected": false
  }'

  _check_vpn_killswitch

  assert_recorded fail "VPN killswitch is OFF"
}

@test "Mullvad settings without the key — skip-advisory (unknown)" {
  load_script
  setup_killswitch_sandbox
  write_mullvad_settings '{
    "tunnel_options": {}
  }'

  _check_vpn_killswitch

  assert_recorded skip "verify killswitch"
}

@test "ProtonVPN config dir present — skip-advisory" {
  load_script
  setup_killswitch_sandbox
  make_protonvpn_present

  _check_vpn_killswitch

  assert_recorded skip "verify killswitch"
  [[ "${RESULTS_SKIP[*]}" == *"protonvpn"* ]]
}

@test "NordVPN config dir present — skip-advisory" {
  load_script
  setup_killswitch_sandbox
  make_nordvpn_present

  _check_vpn_killswitch

  assert_recorded skip "verify killswitch"
  [[ "${RESULTS_SKIP[*]}" == *"nordvpn"* ]]
}

@test "Mullvad on + ProtonVPN advisory — overall stays advisory (most-pessimistic minus fail wins)" {
  load_script
  setup_killswitch_sandbox
  write_mullvad_settings '{"block_when_disconnected": true}'
  make_protonvpn_present

  _check_vpn_killswitch

  # Advisory takes precedence over the verified Mullvad pass because
  # we can't confirm ProtonVPN's killswitch state.
  assert_recorded skip "verify killswitch"
}

@test "Mullvad off + ProtonVPN advisory — fail dominates" {
  load_script
  setup_killswitch_sandbox
  write_mullvad_settings '{"block_when_disconnected": false}'
  make_protonvpn_present

  _check_vpn_killswitch

  assert_recorded warn "VPN killswitch is OFF"
}

@test "brand names suppressed under --redact" {
  load_script
  setup_killswitch_sandbox
  REDACT=true
  make_protonvpn_present

  _check_vpn_killswitch

  [[ "${RESULTS_SKIP[*]}" != *"protonvpn"* ]]
  assert_recorded skip "verify killswitch / always-on manually"
}

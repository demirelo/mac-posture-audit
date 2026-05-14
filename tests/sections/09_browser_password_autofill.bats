#!/usr/bin/env bats

load '../helpers'

# Tests for _check_browser_password_autofill. The helper greps Chromium
# Preferences JSON across detected browsers / profiles for the
# native-autofill-disabled signal.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

write_chrome_prefs() {
  local profile="$1" body="$2"
  local dir="$HOME/Library/Application Support/Google/Chrome/$profile"
  mkdir -p "$dir"
  printf '%s' "$body" >"$dir/Preferences"
}

write_brave_prefs() {
  local profile="$1" body="$2"
  local dir="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/$profile"
  mkdir -p "$dir"
  printf '%s' "$body" >"$dir/Preferences"
}

@test "no browser data dirs — skip" {
  load_script
  isolate_home

  _check_browser_password_autofill

  assert_recorded skip "No Chromium browser profiles found"
}

@test "Chrome Default with credentials_enable_service:false — pass" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"credentials_enable_service":false,"other":1}'

  _check_browser_password_autofill

  assert_recorded pass "password manager / autofill disabled"
}

@test "Chrome Default with credentials_enable_service:true — skip-advisory" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded skip "Browser native password manager enabled: Chrome:Default"
}

@test "Chrome Default with the key absent — counts as enabled (Chromium default-on)" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"other_setting":1}'

  _check_browser_password_autofill

  assert_recorded skip "Browser native password manager enabled"
}

@test "multiple profiles — only enabled ones listed" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"credentials_enable_service":false}'
  write_chrome_prefs "Profile 1" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded skip "Browser native password manager enabled: Chrome:Profile 1"
  [[ "${RESULTS_SKIP[*]}" != *"Chrome:Default"* ]]
}

@test "Chrome + Brave both with autofill enabled — both listed" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'
  write_brave_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded skip "Chrome:Default"
  [[ "${RESULTS_SKIP[*]}" == *"Brave:Default"* ]]
}

@test "Chrome + Brave both with autofill disabled — pass with both counted" {
  load_script
  isolate_home
  write_chrome_prefs "Default" '{"credentials_enable_service":false}'
  write_brave_prefs "Default" '{"credentials_enable_service":false}'

  _check_browser_password_autofill

  assert_recorded pass "checked profiles (2)"
}

@test "web3 profile escalates skip to warn" {
  load_script
  isolate_home
  PROFILE="web3"
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded warn "Browser native password manager enabled"
}

@test "founder profile escalates skip to warn" {
  load_script
  isolate_home
  PROFILE="founder"
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded warn "Browser native password manager enabled"
}

@test "paranoid profile escalates skip to warn" {
  load_script
  isolate_home
  PROFILE="paranoid"
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  assert_recorded warn "Browser native password manager enabled"
}

@test "brand:profile names suppressed under --redact" {
  load_script
  isolate_home
  REDACT=true
  write_chrome_prefs "Default" '{"credentials_enable_service":true}'

  _check_browser_password_autofill

  [[ "${RESULTS_SKIP[*]}" != *"Chrome:Default"* ]]
  assert_recorded skip "1 of 1 browser profile(s) have native password manager"
}

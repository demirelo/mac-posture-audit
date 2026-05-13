#!/usr/bin/env bats

load '../helpers'

# Section 09 covers three checks: browser.installed (count), browser.default
# (LaunchServices plist parse), and browser.version_currency (bundle mtime).
#
# The first two are not exercised in this file — they hit hardcoded
# /Applications paths and the real LaunchServices plist on the developer's
# Mac; they're indirectly covered by the live JSON-validation integration
# test. These cases focus on browser.version_currency, which is the
# only Section 09 check parameterised by APP_ROOTS.

setup_browser_sandbox() {
  TEST_APPS="$BATS_TEST_TMPDIR/apps"
  mkdir -p "$TEST_APPS"
  APP_ROOTS=("$TEST_APPS")
  export APP_ROOTS
  # The LaunchServices plist parse is a `plutil ... | awk ...` pipeline,
  # and the script runs with `set -uo pipefail`. Bats test bodies use
  # `set -e`, so an exit-1 mock makes the pipeline (and therefore the
  # whole section) exit before reaching browser.version_currency. We
  # mock to exit 0 with no output — the awk script then produces no
  # match, DEFAULT_BROWSER stays empty, and the function falls through
  # to the version-currency block we actually want to test.
  mock_cli_script plutil $'#!/usr/bin/env bash\nexit 0'
}

# Create a browser bundle and set its mtime to N days ago.
# `touch -t` on macOS takes [[CC]YY]MMDDhhmm[.SS].
make_browser_aged() {
  local bundle_name="$1" age_days="$2"
  local bundle="$TEST_APPS/$bundle_name"
  mkdir -p "$bundle"
  # Compute the timestamp N days ago in the touch -t format.
  local stamp
  stamp=$(date -v -"${age_days}"d +%Y%m%d%H%M)
  touch -t "$stamp" "$bundle"
}

@test "no non-Safari browser installed — skip with N/A" {
  load_script
  setup_browser_sandbox

  section_09_browsers

  assert_recorded skip "No non-Safari browser installed"
}

@test "fresh Chrome bundle (1 day) — passes" {
  load_script
  setup_browser_sandbox
  make_browser_aged "Google Chrome.app" 1

  section_09_browsers

  assert_recorded pass "All installed non-Safari browsers updated within 28 days"
}

@test "stale Chrome bundle (40 days) — warns with age in label" {
  load_script
  setup_browser_sandbox
  make_browser_aged "Google Chrome.app" 40

  section_09_browsers

  assert_recorded warn "Chrome"
  [[ "${RESULTS_WARN[*]}" == *"40d"* ]] || [[ "${RESULTS_WARN[*]}" == *"39d"* ]] || [[ "${RESULTS_WARN[*]}" == *"41d"* ]]
}

@test "fresh Brave + stale Firefox — only Firefox flagged" {
  load_script
  setup_browser_sandbox
  make_browser_aged "Brave Browser.app" 5
  make_browser_aged "Firefox.app" 50

  section_09_browsers

  # The browser.installed row (which uses hardcoded /Applications paths,
  # not APP_ROOTS) can independently mention "Brave" when the developer
  # running the suite has Brave installed. Pin the assertion to the
  # specific version_currency JSON row.
  ver_row=$(printf '%s\n' "${JSON_ROWS[@]}" | grep '"browser.version_currency"')
  [[ -n "$ver_row" ]]
  [[ "$ver_row" == *"Firefox"* ]]
  [[ "$ver_row" != *"Brave"* ]]
}

@test "multiple stale browsers — all listed" {
  load_script
  setup_browser_sandbox
  make_browser_aged "Google Chrome.app" 35
  make_browser_aged "Microsoft Edge.app" 45
  make_browser_aged "Firefox.app" 60

  section_09_browsers

  assert_recorded warn "Chrome"
  [[ "${RESULTS_WARN[*]}" == *"Edge"* ]]
  [[ "${RESULTS_WARN[*]}" == *"Firefox"* ]]
}

@test "stale browser — web3 profile escalates warn to fail" {
  load_script
  setup_browser_sandbox
  PROFILE="web3"
  make_browser_aged "Google Chrome.app" 40

  section_09_browsers

  assert_recorded fail "Chrome"
}

@test "stale browser — paranoid profile escalates warn to fail" {
  load_script
  setup_browser_sandbox
  PROFILE="paranoid"
  make_browser_aged "Brave Browser.app" 35

  section_09_browsers

  assert_recorded fail "Brave"
}

@test "stale browser names suppressed under --redact" {
  load_script
  setup_browser_sandbox
  REDACT=true
  make_browser_aged "Google Chrome.app" 40

  section_09_browsers

  [[ "${RESULTS_WARN[*]}" != *"Chrome"* ]]
  [[ "${RESULTS_WARN[*]}" == *"1 browser"* ]] || [[ "${RESULTS_WARN[*]}" == *"browser(s)"* ]]
}

@test "near-threshold inside (27 days) — counted as fresh" {
  load_script
  setup_browser_sandbox
  # Threshold is age > 28*86400. At 27 days, comfortably fresh.
  make_browser_aged "Arc.app" 27

  section_09_browsers

  assert_recorded pass "All installed non-Safari browsers updated within 28 days"
}

@test "near-threshold outside (29 days) — counted as stale" {
  load_script
  setup_browser_sandbox
  make_browser_aged "Arc.app" 29

  section_09_browsers

  assert_recorded warn "Arc"
}

# ─── browser.profile_count ────────────────────────────────────────────────
# The profile-counting block reads from $HOME, so we isolate HOME to a
# tmpdir and seed the relevant Chromium / Firefox profile dirs.

setup_profile_sandbox() {
  setup_browser_sandbox
  PROFILE_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$PROFILE_HOME"
  export HOME="$PROFILE_HOME"
}

write_chrome_profile() {
  local name="$1"
  local p="$PROFILE_HOME/Library/Application Support/Google/Chrome/$name"
  mkdir -p "$p"
  : >"$p/Preferences"
}

write_brave_profile() {
  local name="$1"
  local p="$PROFILE_HOME/Library/Application Support/BraveSoftware/Brave-Browser/$name"
  mkdir -p "$p"
  : >"$p/Preferences"
}

write_firefox_profile() {
  local name="$1"
  local p="$PROFILE_HOME/Library/Application Support/Firefox/Profiles/$name"
  mkdir -p "$p"
}

@test "no browser data dirs — skip with 'none enumerable'" {
  load_script
  setup_profile_sandbox
  section_09_browsers
  assert_recorded skip "Browser profiles: none enumerable"
}

@test "single Chrome Default profile — skip with nudge to add a second" {
  load_script
  setup_profile_sandbox
  write_chrome_profile "Default"
  section_09_browsers
  assert_recorded skip "Single browser profile in use"
}

@test "Default + Profile 1 in Chrome — passes (multiple profiles)" {
  load_script
  setup_profile_sandbox
  write_chrome_profile "Default"
  write_chrome_profile "Profile 1"
  section_09_browsers
  assert_recorded pass "Multiple browser profiles"
  [[ "${RESULTS_PASS[*]}" == *"Chrome:2"* ]]
}

@test "Chrome Default + Brave Default — counts both browsers" {
  load_script
  setup_profile_sandbox
  write_chrome_profile "Default"
  write_brave_profile "Default"
  section_09_browsers
  assert_recorded pass "Multiple browser profiles"
  [[ "${RESULTS_PASS[*]}" == *"Chrome:1"* ]]
  [[ "${RESULTS_PASS[*]}" == *"Brave:1"* ]]
}

@test "Firefox with two profile dirs — counted" {
  load_script
  setup_profile_sandbox
  write_firefox_profile "abc123.default-release"
  write_firefox_profile "xyz789.dev"
  section_09_browsers
  assert_recorded pass "Multiple browser profiles"
  [[ "${RESULTS_PASS[*]}" == *"Firefox:2"* ]]
}

@test "Chrome profile names redacted under --redact" {
  load_script
  setup_profile_sandbox
  REDACT=true
  write_chrome_profile "Default"
  write_chrome_profile "Profile 1"
  section_09_browsers
  assert_recorded pass "Multiple browser profiles"
  [[ "${RESULTS_PASS[*]}" != *"Chrome:"* ]]
}

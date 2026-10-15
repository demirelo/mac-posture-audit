#!/usr/bin/env bats

# Cover only the auto-update branch of section 21. The full section also
# does Find My Mac, but that requires multiple plist files we don't need
# to assemble for B.2 coverage.

load '../helpers.bash'

setup() {
  load_script
}

# Mock softwareupdate so it never returns "Automatic background checks: On"
# (i.e. we exercise the fallback path that previously had the tautology bug).
mock_softwareupdate_silent() {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nexit 0'
}

# Mock defaults to return whatever ACE value the test wants.
mock_defaults_ace() {
  local ace="$1"
  mock_cli_script defaults "#!/usr/bin/env bash
case \"\$*\" in
  *AutomaticCheckEnabled*) printf '%s\\n' \"$ace\" ;;
  *) exit 1 ;;
esac"
}

@test "auto-update: AutomaticCheckEnabled=1 -> pass" {
  mock_softwareupdate_silent
  mock_defaults_ace 1
  _check_update_auto
  assert_recorded pass "AutomaticCheckEnabled=1"
}

@test "auto-update: AutomaticCheckEnabled=0 -> warn (not a false PASS via unrelated keys)" {
  # Regression for B.2: the previous fallback loop OR'd six unrelated
  # defaults keys (AutomaticDownload, CriticalUpdateInstall, etc.) and
  # emitted PASS the moment any was 1 — even when AutomaticCheckEnabled=0
  # explicitly turned off the schedule.
  mock_softwareupdate_silent
  mock_defaults_ace 0
  _check_update_auto
  assert_recorded warn "Automatic update checks are off"
}

@test "auto-update: key absent -> skip (not warn, since the answer is unknown)" {
  mock_softwareupdate_silent
  mock_defaults_ace ""
  _check_update_auto
  assert_recorded skip "state unreadable"
}

@test "auto-update: softwareupdate --schedule says On -> pass (preferred canonical path)" {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nprintf "Automatic background checks: On\\n"\nexit 0'
  # Don't even need defaults; the first branch should fire.
  _check_update_auto
  assert_recorded pass "Automatic update background checks are on"
}

@test "auto-update: authoritative Off is not overridden by a stale enabled preference" {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nprintf "Automatic background checks: Off\\n"'
  mock_defaults_ace 1
  _check_update_auto
  [ "$(_status_of update.auto)" = warn ]
}

@test "auto-update: failed probes cannot turn partial output into a pass" {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nprintf "Automatic background checks: On\\n"\nexit 1'
  mock_cli_script defaults $'#!/usr/bin/env bash\nprintf "1\\n"\nexit 1'
  _check_update_auto
  [ "$(_status_of update.auto)" = skip ]
}

@test "auto-update: changed schedule text is not accepted as an enabled state" {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nprintf "Unavailable; cached Automatic background checks: On\\n"'
  mock_defaults_ace ""
  _check_update_auto
  [ "$(_status_of update.auto)" = skip ]
}

@test "Background Security Improvements are separate unverified coverage on 26.1 and 27" {
  for version in 26.1 26.5 27.0.1 28.0; do
    reset_state
    MACOS_VER="$version"
    _check_background_security
    [ "$(_status_of update.background_security)" = skip ]
    [[ "${ROW_HINT[*]}" == *'Privacy & Security'* ]]
    [[ "${ROW_HINT[*]}" == *'built-in startup storage'* ]]
  done
}

@test "older macOS versions do not claim Background Security Improvements support" {
  for version in 10.15.7 13.6 15.7 26.0 unknown; do
    reset_state
    MACOS_VER="$version"
    _check_background_security
    [ "$SKIP_N" -eq 0 ]
    [ "$PASS_N" -eq 0 ]
  done
}

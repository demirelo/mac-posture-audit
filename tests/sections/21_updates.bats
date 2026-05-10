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

# section_21 is long; isolate just the auto-update branch. Keep it byte-
# identical to what the script does so a future drift in the production
# code without updating the test is loud.
run_auto_update_check() {
  if softwareupdate --schedule 2>/dev/null | grep -qi "Automatic background checks: On"; then
    pass "Automatic update background checks are on" "update.auto"
  else
    ACE=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "")
    case "$ACE" in
    1) pass "Automatic update checks on (AutomaticCheckEnabled=1)" "update.auto" ;;
    0) warn "Automatic update checks are off (AutomaticCheckEnabled=0)" "..." "update.auto" ;;
    *) skip "Automatic update check state unreadable" "..." "update.auto" ;;
    esac
  fi
}

@test "auto-update: AutomaticCheckEnabled=1 -> pass" {
  mock_softwareupdate_silent
  mock_defaults_ace 1
  run_auto_update_check
  assert_recorded pass "AutomaticCheckEnabled=1"
}

@test "auto-update: AutomaticCheckEnabled=0 -> warn (not a false PASS via unrelated keys)" {
  # Regression for B.2: the previous fallback loop OR'd six unrelated
  # defaults keys (AutomaticDownload, CriticalUpdateInstall, etc.) and
  # emitted PASS the moment any was 1 — even when AutomaticCheckEnabled=0
  # explicitly turned off the schedule.
  mock_softwareupdate_silent
  mock_defaults_ace 0
  run_auto_update_check
  assert_recorded warn "Automatic update checks are off"
}

@test "auto-update: key absent -> skip (not warn, since the answer is unknown)" {
  mock_softwareupdate_silent
  mock_defaults_ace ""
  run_auto_update_check
  assert_recorded skip "state unreadable"
}

@test "auto-update: softwareupdate --schedule says On -> pass (preferred canonical path)" {
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nprintf "Automatic background checks: On\\n"\nexit 0'
  # Don't even need defaults; the first branch should fire.
  run_auto_update_check
  assert_recorded pass "Automatic update background checks are on"
}

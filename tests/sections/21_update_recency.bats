#!/usr/bin/env bats

load '../helpers'

# Tests for _check_update_macos_recency. We mock `softwareupdate` so the
# runner's real update history doesn't influence the test.

mock_softwareupdate() {
  local body="$1"
  mock_cli_script softwareupdate "#!/usr/bin/env bash
cat <<'OUT'
${body}
OUT"
}

# Compose a softwareupdate --history output with a fake "macOS" line N
# days in the past relative to today. macOS-only date arithmetic.
history_with_macos_aged() {
  local age_days="$1"
  local date_str
  date_str=$(date -v -"${age_days}"d +%m/%d/%Y)
  cat <<EOF
Display Name                                        Version    Date              Action
------------                                        -------    ----              ------
macOS Sonoma 14.5                                   14.5       $date_str, 11:23 Installed
EOF
}

@test "softwareupdate not available — skip" {
  load_script
  # Create the empty bin dir BEFORE nuking PATH (otherwise mkdir itself
  # becomes unavailable). After the override, `command -v softwareupdate`
  # finds nothing because the empty dir contains no executables.
  #
  # We save/restore $PATH because bats' per-test teardown runs `rm` to
  # clean up $BATS_TEST_TMPDIR after the test body returns; leaving the
  # restricted PATH in place causes "rm: command not found" and bubbles
  # up as an exit-1 from the bats runner even when every assertion
  # passed.
  empty_bin="$BATS_TEST_TMPDIR/empty-bin"
  mkdir -p "$empty_bin"
  orig_path="$PATH"
  PATH="$empty_bin"

  _check_update_macos_recency

  PATH="$orig_path"
  assert_recorded skip "softwareupdate not available"
}

@test "empty history — skip" {
  load_script
  mock_cli_script softwareupdate $'#!/usr/bin/env bash\nexit 0'

  _check_update_macos_recency

  assert_recorded skip "softwareupdate --history returned no rows"
}

@test "no system-relevant rows in history — skip with parse hint" {
  load_script
  mock_softwareupdate "Display Name                Version    Date              Action
------------                -------    ----              ------
Pages                       14.0       05/01/2024, 10:00 Installed
Keynote                     14.0       05/01/2024, 10:01 Installed"

  _check_update_macos_recency

  assert_recorded skip "Could not parse a system update date"
}

@test "macOS update 10 days ago — pass" {
  load_script
  mock_softwareupdate "$(history_with_macos_aged 10)"

  _check_update_macos_recency

  assert_recorded pass "Most recent macOS / Safari / Security update"
}

@test "macOS update 45 days ago — pass (at threshold inclusive)" {
  load_script
  mock_softwareupdate "$(history_with_macos_aged 45)"

  _check_update_macos_recency

  assert_recorded pass "Most recent macOS / Safari / Security update"
}

@test "macOS update 60 days ago — warn (over 45d threshold)" {
  load_script
  mock_softwareupdate "$(history_with_macos_aged 60)"

  _check_update_macos_recency

  assert_recorded warn "apply pending updates"
}

@test "macOS update 120 days ago — warn 'significantly behind'" {
  load_script
  mock_softwareupdate "$(history_with_macos_aged 120)"

  _check_update_macos_recency

  assert_recorded warn "significantly behind"
}

@test "paranoid profile escalates >45d warn to fail" {
  load_script
  PROFILE="paranoid"
  mock_softwareupdate "$(history_with_macos_aged 60)"

  _check_update_macos_recency

  assert_recorded fail "apply pending updates"
}

@test "multiple installs — most recent wins" {
  load_script
  local recent stale
  recent=$(date -v -10d +%m/%d/%Y)
  stale=$(date -v -200d +%m/%d/%Y)
  mock_softwareupdate "Display Name                Version    Date              Action
------------                -------    ----              ------
macOS Sonoma 14.4           14.4       $stale, 09:00 Installed
Safari 17.5                 17.5       $recent, 11:23 Installed"

  _check_update_macos_recency

  assert_recorded pass "Most recent macOS / Safari / Security update"
}

@test "Security Update entry counts as system-relevant" {
  load_script
  local date_str
  date_str=$(date -v -20d +%m/%d/%Y)
  mock_softwareupdate "Display Name                Version    Date              Action
------------                -------    ----              ------
Security Update 2024-001    1.0        $date_str, 09:00 Installed"

  _check_update_macos_recency

  assert_recorded pass "Most recent macOS / Safari / Security update"
}

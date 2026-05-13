#!/usr/bin/env bats

load '../helpers'

# Section 25 currently covers Telegram Desktop. The check is *advisory*:
# tdata is encrypted and we can't read settings directly, so we emit
# skip-with-hint when present, pass when absent.

setup_app_roots_sandbox() {
  TEST_APPS="$BATS_TEST_TMPDIR/apps"
  mkdir -p "$TEST_APPS"
  APP_ROOTS=("$TEST_APPS")
  export APP_ROOTS
}

@test "Telegram absent — passes" {
  load_script
  setup_app_roots_sandbox

  section_25_messaging

  assert_recorded pass "Telegram Desktop not installed"
}

@test "Telegram.app present — skip-with-advisory" {
  load_script
  setup_app_roots_sandbox
  mkdir -p "$TEST_APPS/Telegram.app"

  section_25_messaging

  assert_recorded skip "Telegram Desktop installed"
  [[ "${RESULTS_SKIP[*]}" == *"verify privacy defaults manually"* ]]
}

@test "Telegram Desktop.app (vendor variant) present — also detected" {
  load_script
  setup_app_roots_sandbox
  mkdir -p "$TEST_APPS/Telegram Desktop.app"

  section_25_messaging

  assert_recorded skip "Telegram Desktop installed"
}

@test "Telegram Lite (App Store variant) present — also detected" {
  load_script
  setup_app_roots_sandbox
  mkdir -p "$TEST_APPS/Telegram Lite.app"

  section_25_messaging

  assert_recorded skip "Telegram Desktop installed"
}

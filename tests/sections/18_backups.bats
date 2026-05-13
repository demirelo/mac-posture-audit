#!/usr/bin/env bats

load '../helpers'

@test "Time Machine reports missing destinations and missing latest backup" {
  load_script
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/no_destinations.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded warn "No Time Machine destinations configured"
  assert_recorded skip "Time Machine: no recent backup found"
}

@test "Time Machine destination parser records configured destination" {
  load_script
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/destination.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded pass "Time Machine destination configured: BackupDisk"
}

@test "Time Machine encryption — passes for Encrypted:1" {
  load_script
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/destination_encrypted.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded pass "Time Machine destination is encrypted"
}

@test "Time Machine encryption — warns for Encrypted:0" {
  load_script
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/destination_unencrypted.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded warn "Time Machine destination is unencrypted"
}

@test "Time Machine encryption — skips when no destination configured" {
  load_script
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/no_destinations.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded skip "Time Machine has no destination configured"
}

@test "Time Machine encryption — skips when Encrypted field absent (older tmutil)" {
  load_script
  # destination.txt (the original fixture) has no Encrypted line — simulates older macOS.
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/destination.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded skip "Time Machine encryption status not exposed"
}

@test "Time Machine encryption — paranoid profile escalates warn to fail" {
  load_script
  PROFILE="paranoid"
  mock_cli_script tmutil '#!/usr/bin/env bash
case "$1" in
  destinationinfo) cat "$FIXTURE_ROOT/tmutil/destination_unencrypted.txt" ;;
  latestbackup) cat "$FIXTURE_ROOT/tmutil/no_latest.txt" ;;
  *) exit 1 ;;
esac'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'

  section_18_backups

  assert_recorded fail "Time Machine destination is unencrypted"
}

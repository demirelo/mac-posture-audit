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

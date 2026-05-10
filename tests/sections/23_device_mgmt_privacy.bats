#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
}

# `defaults` reads com.apple.screencapture location. Stub it.
mock_defaults() {
  mock_cli_script defaults "#!/usr/bin/env bash
case \"\$*\" in
  *com.apple.screencapture*) printf '%s' \"\${MOCK_SCREENSHOT_LOC:-}\" ;;
  *) exit 1 ;;
esac"
}

# `profiles status -type enrollment` stub.
mock_profiles() {
  mock_cli_script profiles "#!/usr/bin/env bash
case \"\$*\" in
  'status -type enrollment') printf '%s' \"\${MOCK_MDM_OUT:-}\" ;;
  *) exit 1 ;;
esac"
}

# GitHub macOS runners give the runner user passwordless sudo, so a bare
# `sudo -n profiles ...` succeeds against the REAL /usr/bin/profiles and
# bypasses our mock. Stub sudo with a transparent passthrough that strips
# `-n` (and a few common flags) and execs the rest, so the resolved
# command picks up the mocked binary on PATH.
mock_sudo_passthrough() {
  mock_cli_script sudo '#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|-S|-H|-E) shift ;;
    -u) shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"'
}

@test "MDM not enrolled -> pass" {
  mock_defaults
  mock_profiles
  mock_sudo_passthrough
  MOCK_MDM_OUT=$'Enrolled via DEP: No\nMDM enrollment: No'
  export MOCK_MDM_OUT
  QUICK=false

  section_23_device_mgmt_privacy

  assert_recorded pass "Not MDM-enrolled"
}

@test "MDM enrolled -> skip with details" {
  mock_defaults
  mock_profiles
  mock_sudo_passthrough
  MOCK_MDM_OUT=$'Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)'
  export MOCK_MDM_OUT
  QUICK=false

  section_23_device_mgmt_privacy

  assert_recorded skip "MDM-enrolled"
}

@test "QUICK skips MDM check" {
  mock_defaults
  mock_profiles
  QUICK=true

  section_23_device_mgmt_privacy

  assert_recorded skip "MDM enrollment status (requires sudo)"
}

@test "screenshot location empty -> pass (~/Desktop default)" {
  mock_defaults
  mock_profiles
  MOCK_SCREENSHOT_LOC=""
  export MOCK_SCREENSHOT_LOC

  section_23_device_mgmt_privacy

  assert_recorded pass "Screenshots save to default ~/Desktop"
}

@test "screenshot location in iCloud -> warn" {
  mock_defaults
  mock_profiles
  MOCK_SCREENSHOT_LOC="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Screenshots"
  export MOCK_SCREENSHOT_LOC

  section_23_device_mgmt_privacy

  assert_recorded warn "Screenshots save to an iCloud-synced folder"
}

@test "screenshot location in Dropbox -> warn" {
  mock_defaults
  mock_profiles
  MOCK_SCREENSHOT_LOC="$HOME/Dropbox/Screenshots"
  export MOCK_SCREENSHOT_LOC

  section_23_device_mgmt_privacy

  assert_recorded warn "Screenshots save to a cloud-synced folder"
}

@test "screenshot location in local folder -> pass" {
  mock_defaults
  mock_profiles
  MOCK_SCREENSHOT_LOC="$HOME/Pictures/Screenshots"
  export MOCK_SCREENSHOT_LOC

  section_23_device_mgmt_privacy

  assert_recorded pass "Screenshots save to a local folder"
}

@test "no clipboard manager detected -> pass" {
  mock_defaults
  mock_profiles
  # pgrep stub that always fails so process detection is empty.
  mock_cli_script pgrep '#!/usr/bin/env bash
exit 1'

  section_23_device_mgmt_privacy

  assert_recorded pass "No clipboard-manager-with-history app detected"
}

@test "clipboard manager process running -> skip with details" {
  mock_defaults
  mock_profiles
  # pgrep matches "maccy"
  mock_cli_script pgrep '#!/usr/bin/env bash
case "$*" in
  *maccy*) exit 0 ;;
  *) exit 1 ;;
esac'

  section_23_device_mgmt_privacy

  assert_recorded skip "Clipboard manager(s) detected: Maccy"
}

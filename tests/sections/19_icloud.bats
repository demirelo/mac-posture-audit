#!/usr/bin/env bats

load '../helpers'

# Section 19 has several pre-existing checks (icloud.signedin, savetocloud,
# adp, drive.active) that are exercised by integration tests. These cases
# focus on cloud.icloud.desktop_documents_sync — the redirected-folder
# detection that complements §17's cloud_sync_exposure checks.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

# Quiet the launchctl / plutil / brctl / defaults probes so the rest of
# section_19 doesn't crash the test on a Linux runner without those tools.
mock_section_19_deps() {
  mock_cli_script plutil '#!/usr/bin/env bash
exit 1'
  mock_cli_script launchctl '#!/usr/bin/env bash
exit 1'
  mock_cli_script brctl '#!/usr/bin/env bash
exit 1'
  mock_cli_script defaults '#!/usr/bin/env bash
exit 1'
}

@test "no iCloud Mobile Documents directory at all — desktop+documents sync passes" {
  load_script
  isolate_home
  mock_section_19_deps

  section_19_icloud

  assert_recorded pass "iCloud Desktop & Documents Folders sync is off"
}

@test "iCloud Drive root present but no Desktop/Documents — passes" {
  load_script
  isolate_home
  mock_section_19_deps
  # Just the root container, no redirected folders inside
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs"

  section_19_icloud

  assert_recorded pass "iCloud Desktop & Documents Folders sync is off"
}

@test "Desktop redirected to iCloud — warns" {
  load_script
  isolate_home
  mock_section_19_deps
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Desktop"

  section_19_icloud

  assert_recorded warn "iCloud 'Desktop & Documents Folders' sync is on"
  [[ "${RESULTS_WARN[*]}" == *"Desktop"* ]]
}

@test "Documents redirected to iCloud — warns" {
  load_script
  isolate_home
  mock_section_19_deps
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Documents"

  section_19_icloud

  assert_recorded warn "iCloud 'Desktop & Documents Folders' sync is on"
  [[ "${RESULTS_WARN[*]}" == *"Documents"* ]]
}

@test "Both Desktop and Documents redirected — label lists both" {
  load_script
  isolate_home
  mock_section_19_deps
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Desktop"
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Documents"

  section_19_icloud

  assert_recorded warn "Desktop"
  [[ "${RESULTS_WARN[*]}" == *"Documents"* ]]
}

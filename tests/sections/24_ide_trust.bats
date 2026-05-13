#!/usr/bin/env bats

load '../helpers'

# Section 24 covers two things:
#   1. IDE workspace trust per-IDE rows (ide.vscode.workspace_trust,
#      ide.cursor.workspace_trust)
#   2. users.crypto_isolation_indicator cross-section composite
#
# The IDE checks read files from a synthetic $HOME under $BATS_TEST_TMPDIR.
# The composite reads STATUS_BY_ID, which we populate by setting it
# directly via the helper below — that's far easier than orchestrating
# four upstream sections in every case.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
  # Sandbox the IDE app lookup so detection doesn't depend on whether
  # the developer running the suite has VS Code / Cursor installed.
  IDE_TEST_APPS="$BATS_TEST_TMPDIR/apps"
  mkdir -p "$IDE_TEST_APPS"
  IDE_APP_ROOTS=("$IDE_TEST_APPS")
  export IDE_APP_ROOTS
}

vscode_settings_path() {
  printf '%s/Library/Application Support/Code/User/settings.json' "$HOME"
}

cursor_settings_path() {
  printf '%s/Library/Application Support/Cursor/User/settings.json' "$HOME"
}

write_vscode_settings() {
  local content="$1"
  local p
  p="$(vscode_settings_path)"
  mkdir -p "$(dirname "$p")"
  printf '%s\n' "$content" >"$p"
}

write_cursor_settings() {
  local content="$1"
  local p
  p="$(cursor_settings_path)"
  mkdir -p "$(dirname "$p")"
  printf '%s\n' "$content" >"$p"
}

# Pre-seed STATUS_BY_ID for the composite. _status_of() returns "" for
# any ID not in this string, so the composite handles missing
# dependencies the same as in production.
set_status() {
  STATUS_BY_ID="$STATUS_BY_ID $1=$2 "
}

# ─── IDE workspace trust ──────────────────────────────────────────────────

@test "no IDE installed — both per-IDE rows skip" {
  load_script
  isolate_home
  # APP_ROOTS isn't used by section 24 but keep tests hermetic
  section_24_ide_trust
  assert_recorded skip "VS Code not detected"
  assert_recorded skip "Cursor not detected"
}

@test "VS Code installed with no settings.json — pass with default trust" {
  load_script
  isolate_home
  mkdir -p "$IDE_TEST_APPS/Visual Studio Code.app"
  section_24_ide_trust
  assert_recorded pass "VS Code installed; no user settings"
}

@test "VS Code settings.json with workspace trust disabled — fails" {
  load_script
  isolate_home
  write_vscode_settings '{
    "editor.fontSize": 13,
    "security.workspace.trust.enabled": false
  }'
  section_24_ide_trust
  assert_recorded fail "VS Code workspace trust posture"
  [[ "${RESULTS_FAIL[*]}" == *"workspace trust DISABLED"* ]]
}

@test "VS Code settings.json with untrustedFiles=open — warns" {
  load_script
  isolate_home
  write_vscode_settings '{
    "security.workspace.trust.untrustedFiles": "open"
  }'
  section_24_ide_trust
  assert_recorded warn "VS Code workspace trust posture"
  [[ "${RESULTS_WARN[*]}" == *"auto-open"* ]]
}

@test "VS Code settings.json with startupPrompt=never — warns" {
  load_script
  isolate_home
  write_vscode_settings '{
    "security.workspace.trust.startupPrompt": "never"
  }'
  section_24_ide_trust
  assert_recorded warn "VS Code workspace trust posture"
  [[ "${RESULTS_WARN[*]}" == *"startup prompt suppressed"* ]]
}

@test "VS Code with all three opt-outs — fails (disable dominates)" {
  load_script
  isolate_home
  write_vscode_settings '{
    "security.workspace.trust.enabled": false,
    "security.workspace.trust.untrustedFiles": "open",
    "security.workspace.trust.startupPrompt": "never"
  }'
  section_24_ide_trust
  assert_recorded fail "VS Code workspace trust posture"
}

@test "VS Code clean settings.json — passes" {
  load_script
  isolate_home
  write_vscode_settings '{
    "editor.fontSize": 13,
    "files.autoSave": "afterDelay"
  }'
  section_24_ide_trust
  assert_recorded pass "VS Code: workspace trust at defaults"
}

@test "Cursor settings.json with workspace trust disabled — fails on Cursor only" {
  load_script
  isolate_home
  write_cursor_settings '{
    "security.workspace.trust.enabled": false
  }'
  section_24_ide_trust
  assert_recorded fail "Cursor workspace trust posture"
  # VS Code path should still be a skip — not installed.
  assert_recorded skip "VS Code not detected"
}

@test "Cursor disabled — web3 profile keeps fail (no escalation needed)" {
  load_script
  isolate_home
  PROFILE="web3"
  write_cursor_settings '{
    "security.workspace.trust.enabled": false
  }'
  section_24_ide_trust
  assert_recorded fail "Cursor workspace trust posture"
}

@test "Cursor untrustedFiles=open — web3 profile escalates warn to fail" {
  load_script
  isolate_home
  PROFILE="web3"
  write_cursor_settings '{
    "security.workspace.trust.untrustedFiles": "open"
  }'
  section_24_ide_trust
  assert_recorded fail "Cursor workspace trust posture"
}

# ─── users.crypto_isolation_indicator ─────────────────────────────────────

@test "no wallet detected — composite skips with N/A" {
  load_script
  isolate_home
  set_status "ext.wallet" "pass"
  set_status "user.human.count" "skip"
  set_status "browser.default" "warn"
  section_24_ide_trust
  assert_recorded skip "Wallet isolation N/A"
}

@test "wallet detected, multi-user + non-default-browser — composite passes" {
  load_script
  isolate_home
  set_status "ext.wallet" "warn"
  set_status "user.human.count" "pass"
  set_status "browser.default" "pass"
  section_24_ide_trust
  assert_recorded pass "Wallet workflow shows isolation indicators"
}

@test "wallet detected on single-user Mac — composite warns" {
  load_script
  isolate_home
  set_status "ext.wallet" "warn"
  set_status "user.human.count" "skip"
  set_status "browser.default" "pass"
  section_24_ide_trust
  assert_recorded warn "single user account on this Mac"
}

@test "wallet detected and default browser is risky — composite warns" {
  load_script
  isolate_home
  set_status "ext.wallet" "warn"
  set_status "user.human.count" "pass"
  set_status "browser.default" "warn"
  section_24_ide_trust
  assert_recorded warn "default browser is the same risk surface"
}

@test "wallet detected with both gaps — composite warns with combined label" {
  load_script
  isolate_home
  set_status "ext.wallet" "warn"
  set_status "user.human.count" "skip"
  set_status "browser.default" "warn"
  section_24_ide_trust
  assert_recorded warn "single user account"
  [[ "${RESULTS_WARN[*]}" == *"default browser"* ]]
}

@test "wallet escalated to fail under web3 — composite still fires + escalates" {
  load_script
  isolate_home
  PROFILE="web3"
  set_status "ext.wallet" "fail"
  set_status "user.human.count" "skip"
  set_status "browser.default" "warn"
  section_24_ide_trust
  # Profile override rewrites users.crypto_isolation_indicator warn → fail
  assert_recorded fail "Wallet isolation gaps"
}

#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  # Force HOME to a tmpdir so we can deterministically control LaunchAgents.
  TEST_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$TEST_HOME/Library/LaunchAgents"
  HOME="$TEST_HOME"
}

mock_osascript_empty() {
  mock_cli_script osascript $'#!/usr/bin/env bash\nprintf "\\n"\nexit 0'
}

mock_osascript_with_items() {
  mock_cli_script osascript $'#!/usr/bin/env bash\necho "Slack, Discord"\nexit 0'
}

mock_osascript_denied() {
  # Simulate the exact error osascript prints when the terminal lacks
  # Automation permission for System Events on macOS 14/15.
  mock_cli_script osascript $'#!/usr/bin/env bash\nprintf "execution error: Not authorised to send Apple events to System Events. (-1743)\\n" >&2\nexit 1'
}

mock_osascript_generic_error() {
  # osascript can fail for reasons other than the Automation-denied path —
  # e.g. an internal Apple Events error. The previous "elif -n $LOGIN_OUT"
  # branch would then misreport the stderr as login-item names. The fix
  # must instead emit a SKIP that mentions the exit code.
  mock_cli_script osascript $'#!/usr/bin/env bash\nprintf "execution error: System Events got an error: AppleEvent handler failed. (-10000)\\n" >&2\nexit 1'
}

mock_crontab_empty() {
  mock_cli_script crontab $'#!/usr/bin/env bash\nexit 1'
}

mock_crontab_with_entries() {
  mock_cli_script crontab $'#!/usr/bin/env bash\nprintf "# header\\n0 9 * * * /usr/bin/foo\\n"\nexit 0'
}

mock_sudo_tcc_passthrough() {
  mock_cli_script sudo '#!/usr/bin/env bash
[[ "$1" == "-n" ]] && shift
case "$1" in
  test) exit 0 ;;
  *) exec "$@" ;;
esac'
}

mock_sqlite_tcc_modern() {
  mock_cli_script sqlite3 '#!/usr/bin/env bash
db="$2"
sql="$3"
case "$sql" in
  "PRAGMA table_info(access);")
    printf "0|service|TEXT|1||1\n1|client|TEXT|1||2\n2|auth_value|INTEGER|0||0\n"
    ;;
  *"auth_value=2"*)
    if [[ "$db" == "/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
      printf "kTCCServiceAccessibility|com.example.SystemTool\n"
    else
      printf "kTCCServiceScreenCapture|com.example.UserTool\n"
    fi
    ;;
esac'
}

mock_sqlite_tcc_user_only_clean() {
  mock_cli_script sqlite3 '#!/usr/bin/env bash
db="$2"
sql="$3"
case "$sql" in
  "PRAGMA table_info(access);")
    if [[ "$db" == "/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
      exit 1
    else
      printf "0|service|TEXT|1||1\n1|client|TEXT|1||2\n2|auth_value|INTEGER|0||0\n"
    fi
    ;;
  *"auth_value=2"*) exit 0 ;;
esac'
}

@test "empty user LaunchAgents directory passes" {
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded pass "No user LaunchAgents"
}

@test "user LaunchAgent plists are warned about" {
  : >"$TEST_HOME/Library/LaunchAgents/com.example.agent.plist"
  : >"$TEST_HOME/Library/LaunchAgents/com.example.helper.plist"
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded warn "user LaunchAgent"
}

@test "user LaunchAgent filenames are listed inline in terminal mode" {
  : >"$TEST_HOME/Library/LaunchAgents/com.example.agent.plist"
  : >"$TEST_HOME/Library/LaunchAgents/com.example.helper.plist"
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  MODE="full"
  REDACT=false
  output=$(section_22_persistence_tcc 2>&1) || true
  [[ "$output" == *"com.example.agent.plist"* ]]
  [[ "$output" == *"com.example.helper.plist"* ]]
}

@test "user LaunchAgent filenames are NOT listed under --redact" {
  : >"$TEST_HOME/Library/LaunchAgents/com.example.agent.plist"
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  MODE="full"
  REDACT=true
  output=$(section_22_persistence_tcc 2>&1) || true
  [[ "$output" != *"com.example.agent.plist"* ]]
}

@test "user LaunchAgent filenames are NOT embedded in JSON output" {
  : >"$TEST_HOME/Library/LaunchAgents/com.example.agent.plist"
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  MODE="json"
  REDACT=false
  section_22_persistence_tcc
  la_row=$(printf '%s\n' "${JSON_ROWS[@]}" | grep '"persist.user.launchagents"')
  [[ -n "$la_row" ]]
  [[ "$la_row" != *"com.example.agent.plist"* ]]
}

@test "non-empty crontab is warned about" {
  mock_osascript_empty
  mock_crontab_with_entries
  QUICK=true
  section_22_persistence_tcc
  assert_recorded warn "cron entries for current user"
}

@test "cron entries are listed inline in terminal mode" {
  mock_osascript_empty
  mock_crontab_with_entries
  QUICK=true
  MODE="full"
  REDACT=false
  output=$(section_22_persistence_tcc 2>&1) || true
  [[ "$output" == *"0 9 * * * /usr/bin/foo"* ]]
}

@test "cron entries are NOT listed under --redact" {
  mock_osascript_empty
  mock_crontab_with_entries
  QUICK=true
  MODE="full"
  REDACT=true
  output=$(section_22_persistence_tcc 2>&1) || true
  [[ "$output" != *"/usr/bin/foo"* ]]
}

@test "cron entries are NOT embedded in JSON hint" {
  mock_osascript_empty
  mock_crontab_with_entries
  QUICK=true
  MODE="json"
  REDACT=false
  section_22_persistence_tcc
  cron_row=$(printf '%s\n' "${JSON_ROWS[@]}" | grep '"persist.cron"')
  [[ -n "$cron_row" ]]
  [[ "$cron_row" != *"/usr/bin/foo"* ]]
}

@test "login items are listed via osascript" {
  mock_osascript_with_items
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded skip "login item"
}

@test "osascript Automation-denied error becomes a SKIP, not a silent PASS" {
  mock_osascript_denied
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded skip "Automation permission"
}

@test "osascript non-Automation error becomes a generic SKIP, not '1 login item: error'" {
  # Regression: the previous code's `elif -n "$LOGIN_OUT"` branch would
  # treat osascript's stderr text as the comma-separated names list,
  # producing "1 login item(s): execution error: ...". The fix branches
  # on the captured exit code instead.
  mock_osascript_generic_error
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded skip "osascript exited"
}

@test "login item names suppressed under --redact" {
  mock_osascript_with_items
  mock_crontab_empty
  QUICK=true
  REDACT=true
  section_22_persistence_tcc
  # The label must include the count but NOT the names (which can
  # identify the user from app inventory).
  assert_recorded skip "login item(s) detected"
  [[ "${RESULTS_SKIP[*]}" != *"Slack"* ]]
  [[ "${RESULTS_SKIP[*]}" != *"Discord"* ]]
}

@test "login item names suppressed in JSON output" {
  mock_osascript_with_items
  mock_crontab_empty
  QUICK=true
  MODE="json"
  section_22_persistence_tcc
  login_row=$(printf '%s\n' "${JSON_ROWS[@]}" | grep '"persist.login_items"')
  [[ -n "$login_row" ]]
  [[ "$login_row" != *"Slack"* ]]
  [[ "$login_row" != *"Discord"* ]]
}

@test "QUICK mode skips TCC check" {
  mock_osascript_empty
  mock_crontab_empty
  QUICK=true
  section_22_persistence_tcc
  assert_recorded skip "TCC permission holders (requires sudo)"
}

@test "TCC reads both user and system databases" {
  mkdir -p "$TEST_HOME/Library/Application Support/com.apple.TCC"
  : >"$TEST_HOME/Library/Application Support/com.apple.TCC/TCC.db"
  mock_osascript_empty
  mock_crontab_empty
  mock_sudo_tcc_passthrough
  mock_sqlite_tcc_modern
  QUICK=false
  section_22_persistence_tcc
  assert_recorded skip "TCC: 2 permission grant(s)"
  [[ "${RESULTS_SKIP[*]}" == *"UserTool"* ]]
  [[ "${RESULTS_SKIP[*]}" == *"SystemTool"* ]]
}

@test "TCC partial read is SKIP, not a clean PASS" {
  mkdir -p "$TEST_HOME/Library/Application Support/com.apple.TCC"
  : >"$TEST_HOME/Library/Application Support/com.apple.TCC/TCC.db"
  mock_osascript_empty
  mock_crontab_empty
  mock_sudo_tcc_passthrough
  mock_sqlite_tcc_user_only_clean
  QUICK=false
  section_22_persistence_tcc
  assert_recorded skip "TCC partial scan"
  [[ "${RESULTS_PASS[*]-}" != *"none in the most-sensitive list"* ]]
}

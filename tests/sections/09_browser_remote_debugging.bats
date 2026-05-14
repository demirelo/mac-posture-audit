#!/usr/bin/env bats

load '../helpers'

# Tests for _check_browser_remote_debugging. We mock `ps` so the runner's
# real process list doesn't influence the test, and we isolate $HOME so
# the LaunchAgents + shell rc grep operates on a synthetic environment.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME/Library/LaunchAgents"
  export HOME="$ISOLATED_HOME"
}

mock_ps() {
  local body="$1"
  mock_cli_script ps "#!/usr/bin/env bash
cat <<'OUT'
${body}
OUT"
}

mock_empty_ps() {
  mock_cli_script ps $'#!/usr/bin/env bash\nprintf \'\\n\''
}

@test "no debug flag anywhere — passes" {
  load_script
  isolate_home
  mock_empty_ps

  _check_browser_remote_debugging

  assert_recorded pass "No browsers running or configured with --remote-debugging-port"
}

@test "Chrome running with --remote-debugging-port — fails" {
  load_script
  isolate_home
  mock_ps "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222
/usr/bin/SafeMode"

  _check_browser_remote_debugging

  assert_recorded fail "Browser/Electron with --remote-debugging-port"
  [[ "${RESULTS_FAIL[*]}" == *"Google Chrome"* ]]
}

@test "Brave running with --remote-debugging-port — fails" {
  load_script
  isolate_home
  mock_ps "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser --remote-debugging-port=9223"

  _check_browser_remote_debugging

  assert_recorded fail "Brave Browser"
}

@test "Cursor (Electron) running with --remote-debugging-port — fails" {
  load_script
  isolate_home
  mock_ps "/Applications/Cursor.app/Contents/MacOS/Cursor --remote-debugging-port=9229"

  _check_browser_remote_debugging

  assert_recorded fail "Cursor"
}

@test "non-browser process with the flag — does NOT fail" {
  load_script
  isolate_home
  # Some unrelated tool exposing a debug port — not in our pattern.
  mock_ps "/usr/local/bin/random-tool --remote-debugging-port=9999"

  _check_browser_remote_debugging

  assert_recorded pass "No browsers running or configured"
}

@test "flag in LaunchAgent — warns (persisted)" {
  load_script
  isolate_home
  mock_empty_ps
  cat >"$HOME/Library/LaunchAgents/com.example.chrome-debug.plist" <<'PLIST'
<?xml version="1.0"?>
<plist><dict>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/Google Chrome.app/Contents/MacOS/Google Chrome</string>
    <string>--remote-debugging-port=9222</string>
  </array>
</dict></plist>
PLIST

  _check_browser_remote_debugging

  assert_recorded warn "--remote-debugging-port referenced in"
  [[ "${RESULTS_WARN[*]}" == *"com.example.chrome-debug.plist"* ]]
}

@test "flag in shell rc — warns (persisted)" {
  load_script
  isolate_home
  mock_empty_ps
  printf 'alias debug-chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222"\n' >"$HOME/.zshrc"

  _check_browser_remote_debugging

  assert_recorded warn ".zshrc"
}

@test "running flag dominates persisted flag (fail wins over warn)" {
  load_script
  isolate_home
  mock_ps "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222"
  printf 'alias debug-chrome="chrome --remote-debugging-port=9222"\n' >"$HOME/.zshrc"

  _check_browser_remote_debugging

  assert_recorded fail "Browser/Electron with --remote-debugging-port"
}

@test "process names suppressed under --redact (running case)" {
  load_script
  isolate_home
  REDACT=true
  mock_ps "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222"

  _check_browser_remote_debugging

  [[ "${RESULTS_FAIL[*]}" != *"Google Chrome"* ]]
  [[ "${RESULTS_FAIL[*]}" == *"1 browser/Electron process(es)"* ]]
}

@test "filenames suppressed under --redact (persisted case)" {
  load_script
  isolate_home
  REDACT=true
  mock_empty_ps
  cat >"$HOME/Library/LaunchAgents/com.example.chrome-debug.plist" <<'PLIST'
<?xml version="1.0"?>
<plist><array>
  <string>--remote-debugging-port=9222</string>
</array></plist>
PLIST

  _check_browser_remote_debugging

  [[ "${RESULTS_WARN[*]}" != *"com.example.chrome-debug.plist"* ]]
  [[ "${RESULTS_WARN[*]}" == *"1 config file(s) reference"* ]]
}

@test "web3 profile escalates persisted warn to fail" {
  load_script
  isolate_home
  PROFILE="web3"
  mock_empty_ps
  printf 'export DEBUG_CHROME="chrome --remote-debugging-port=9222"\n' >"$HOME/.zshrc"

  _check_browser_remote_debugging

  assert_recorded fail "--remote-debugging-port referenced in"
}

@test "paranoid profile escalates persisted warn to fail" {
  load_script
  isolate_home
  PROFILE="paranoid"
  mock_empty_ps
  printf 'alias x="chrome --remote-debugging-port=9222"\n' >"$HOME/.bashrc"

  _check_browser_remote_debugging

  assert_recorded fail ".bashrc"
}

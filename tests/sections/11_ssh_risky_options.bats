#!/usr/bin/env bats

load '../helpers'

# Tests for _check_ssh_config_risky_options. Each test seeds an isolated
# $HOME with a synthetic ~/.ssh/config and calls the helper directly.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME/.ssh"
  export HOME="$ISOLATED_HOME"
}

write_ssh_config() {
  printf '%s\n' "$1" >"$HOME/.ssh/config"
}

@test "no config file — skip" {
  load_script
  isolate_home
  rm -rf "$HOME/.ssh"
  mkdir -p "$HOME/.ssh"

  _check_ssh_config_risky_options

  assert_recorded skip "~/.ssh/config not present"
}

@test "empty config — pass" {
  load_script
  isolate_home
  : >"$HOME/.ssh/config"

  _check_ssh_config_risky_options

  assert_recorded pass "no risky global / Host * options"
}

@test "ForwardAgent yes at global scope — warns" {
  load_script
  isolate_home
  write_ssh_config 'ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded warn "ForwardAgent yes"
}

@test "ForwardAgent yes under Host * — warns" {
  load_script
  isolate_home
  write_ssh_config 'Host *
    ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded warn "ForwardAgent yes"
}

@test "ForwardAgent yes only under specific Host — does NOT warn" {
  load_script
  isolate_home
  write_ssh_config 'Host trusted.internal.example
    ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded pass "no risky global / Host * options"
}

@test "StrictHostKeyChecking no globally — warns" {
  load_script
  isolate_home
  write_ssh_config 'StrictHostKeyChecking no'

  _check_ssh_config_risky_options

  assert_recorded warn "StrictHostKeyChecking no"
}

@test "UserKnownHostsFile /dev/null under Host * — warns" {
  load_script
  isolate_home
  write_ssh_config 'Host *
    UserKnownHostsFile /dev/null'

  _check_ssh_config_risky_options

  assert_recorded warn "UserKnownHostsFile /dev/null"
}

@test "all three risky options under Host * — warns with combined label" {
  load_script
  isolate_home
  write_ssh_config 'Host *
    ForwardAgent yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null'

  _check_ssh_config_risky_options

  assert_recorded warn "ForwardAgent yes"
  [[ "${RESULTS_WARN[*]}" == *"StrictHostKeyChecking no"* ]]
  [[ "${RESULTS_WARN[*]}" == *"UserKnownHostsFile /dev/null"* ]]
}

@test "Match all scope — counted as global" {
  load_script
  isolate_home
  write_ssh_config 'Match all
    ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded warn "ForwardAgent yes"
}

@test "Match host (per-host scope) — does NOT warn" {
  load_script
  isolate_home
  write_ssh_config 'Match host trusted.example
    ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded pass "no risky global / Host * options"
}

@test "developer profile escalates warn to fail" {
  load_script
  isolate_home
  PROFILE="developer"
  write_ssh_config 'ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded fail "ForwardAgent yes"
}

@test "founder profile escalates warn to fail" {
  load_script
  isolate_home
  PROFILE="founder"
  write_ssh_config 'StrictHostKeyChecking no'

  _check_ssh_config_risky_options

  assert_recorded fail "StrictHostKeyChecking no"
}

@test "paranoid profile escalates warn to fail" {
  load_script
  isolate_home
  PROFILE="paranoid"
  write_ssh_config 'UserKnownHostsFile /dev/null'

  _check_ssh_config_risky_options

  assert_recorded fail "UserKnownHostsFile /dev/null"
}

@test "comments and blank lines don't trigger" {
  load_script
  isolate_home
  write_ssh_config '# ForwardAgent yes
# StrictHostKeyChecking no

# everything below is per-host
Host github.com
    ForwardAgent yes'

  _check_ssh_config_risky_options

  assert_recorded pass "no risky global / Host * options"
}

@test "duplicate global + Host * pattern — listed once" {
  load_script
  isolate_home
  write_ssh_config 'ForwardAgent yes
Host *
    ForwardAgent yes'

  _check_ssh_config_risky_options

  # Non-redact label lists the options inline. Dedupe means
  # 'ForwardAgent yes' appears exactly once even though we saw it
  # in two scopes. The label format is
  # "Risky options ... : ForwardAgent yes — Each applies..."; check
  # that "ForwardAgent yes" appears exactly once by comparing the
  # count of "ForwardAgent" occurrences across all recorded labels.
  assert_recorded warn "ForwardAgent yes"
  # RESULTS_WARN stores "label — hint"; the hint itself mentions
  # "ForwardAgent yes" as an example, so we need to look only at the
  # label portion to verify dedup. Strip from " — " onwards.
  label_only="${RESULTS_WARN[0]%% — *}"
  fa_count=$(printf '%s' "$label_only" | grep -o "ForwardAgent" | wc -l | tr -d ' ')
  [[ "$fa_count" -eq 1 ]] || {
    printf 'expected dedup to leave one "ForwardAgent" occurrence in label, saw %s in: %s\n' "$fa_count" "$label_only" >&2
    return 1
  }
}

@test "option name suppressed under --redact, count surfaced" {
  load_script
  isolate_home
  REDACT=true
  write_ssh_config 'Host *
    ForwardAgent yes
    StrictHostKeyChecking no'

  _check_ssh_config_risky_options

  [[ "${RESULTS_WARN[*]}" != *"ForwardAgent yes"* ]]
  [[ "${RESULTS_WARN[*]}" != *"StrictHostKeyChecking no"* ]]
  [[ "${RESULTS_WARN[*]}" == *"2 risky option(s)"* ]]
}

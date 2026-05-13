#!/usr/bin/env bats

load '../helpers'

# Section 17 exercises filesystem state under $HOME. Tests use an isolated
# $HOME under $BATS_TEST_TMPDIR so we never touch the user's real dotfiles.

isolate_home() {
  # By default, place the fake $HOME OUTSIDE any cloud-root path so the
  # *_cloud_sync_exposure checks pass cleanly. Individual tests can override.
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

isolate_home_in_icloud() {
  # Place $HOME under a path that contains "Library/Mobile Documents/
  # com~apple~CloudDocs" so cd+pwd -P returns a path that matches the
  # iCloud Drive pattern in _path_in_cloud_root.
  ISOLATED_HOME="$BATS_TEST_TMPDIR/Library/Mobile Documents/com~apple~CloudDocs/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

@test "folder layout — no sensitive dirs, no cloud exposure" {
  load_script
  isolate_home

  section_17_folder_layout

  assert_recorded skip "No encrypted Vault sparsebundle"
  assert_recorded pass "No SSH / credential dirs inside cloud sync"
  assert_recorded pass "No wallet app data inside cloud sync"
  assert_recorded pass "No tracked dotfiles inside cloud sync"
}

@test "SSH dir inside iCloud Drive — fails" {
  load_script
  isolate_home_in_icloud
  mkdir -p "$HOME/.ssh"

  section_17_folder_layout

  assert_recorded fail "SSH / credential dirs inside cloud sync"
  assert_recorded fail ".ssh → iCloud Drive"
}

@test "AWS + kube dirs inside iCloud Drive — both surfaced" {
  load_script
  isolate_home_in_icloud
  mkdir -p "$HOME/.aws" "$HOME/.kube"

  section_17_folder_layout

  assert_recorded fail ".aws → iCloud Drive"
  assert_recorded fail ".kube → iCloud Drive"
}

@test "wallet app data inside iCloud Drive — warns by default" {
  load_script
  isolate_home_in_icloud
  mkdir -p "$HOME/Library/Application Support/Ledger Live"

  section_17_folder_layout

  assert_recorded warn "Wallet app data inside cloud sync"
  assert_recorded warn "Ledger Live → iCloud Drive"
}

@test "wallet app data inside iCloud Drive — web3 profile escalates to fail" {
  load_script
  PROFILE="web3"
  isolate_home_in_icloud
  mkdir -p "$HOME/Library/Application Support/Trezor Suite"

  section_17_folder_layout

  assert_recorded fail "Wallet app data inside cloud sync"
}

@test "wallet app data inside iCloud Drive — paranoid profile escalates to fail" {
  load_script
  PROFILE="paranoid"
  isolate_home_in_icloud
  mkdir -p "$HOME/Library/Application Support/Bitcoin"

  section_17_folder_layout

  assert_recorded fail "Wallet app data inside cloud sync"
}

@test "dotfiles inside iCloud Drive — warns" {
  load_script
  isolate_home_in_icloud
  : >"$HOME/.zshrc"
  : >"$HOME/.gitconfig"

  section_17_folder_layout

  assert_recorded warn "Dotfiles inside cloud sync"
  assert_recorded warn ".zshrc → iCloud Drive"
  assert_recorded warn ".gitconfig → iCloud Drive"
}

@test "downloads hygiene — fresh + few items passes" {
  load_script
  isolate_home
  mkdir -p "$HOME/Downloads"
  : >"$HOME/Downloads/recent.txt"

  section_17_folder_layout

  assert_recorded pass "Downloads folder: 1 items, none older than 30 days"
}

@test "vault sparsebundle — detected at home root" {
  load_script
  isolate_home
  mkdir -p "$HOME/Vault.sparsebundle"

  section_17_folder_layout

  assert_recorded pass "Encrypted Vault disk image found"
}

#!/usr/bin/env bats

load '../helpers'

setup() {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  unset NPM_CONFIG_USERCONFIG
}

@test "package policy probes never execute npm yarn or pnpm" {
  local name marker="$BATS_TEST_TMPDIR/executed"
  for name in npm yarn pnpm; do
    mock_cli_script "$name" "#!/bin/bash
printf unsafe > '$marker'
exit 99"
  done
  printf 'ignore-scripts=true\n' >"$HOME/.npmrc"
  printf 'enableScripts: false\n' >"$HOME/.yarnrc.yml"
  _check_package_script_policy npm
  _check_package_script_policy yarn
  _check_package_script_policy pnpm
  [ ! -e "$marker" ]
  [ "$(_status_of supply.npm.ignorescripts)" = pass ]
  [ "$(_status_of supply.yarn.ignorescripts)" = pass ]
  [ "$(_status_of supply.pnpm.ignorescripts)" = pass ]
}

@test "npm INI requires equals and ignores section-scoped settings" {
  local line
  for line in 'ignore-scripts: true' 'ignore-scripts true' $'[other]\nignore-scripts=true'; do
    printf '%s\n' "$line" >"$HOME/.npmrc"
    [ "$(_read_config_boolean "$HOME/.npmrc" ignore-scripts)" = unset ]
  done
}

@test "Yarn YAML rejects equals and nested policy keys" {
  local line
  for line in 'enableScripts=false' '  enableScripts: false'; do
    printf '%s\n' "$line" >"$HOME/.yarnrc.yml"
    [ "$(_read_config_boolean "$HOME/.yarnrc.yml" enableScripts yaml)" = unset ]
  done
}

@test "literal booleans use last value and unresolved values remain unknown" {
  printf 'ignore-scripts=true\nignore-scripts=false\n' >"$HOME/.npmrc"
  [ "$(_read_config_boolean "$HOME/.npmrc" ignore-scripts)" = false ]
  printf 'ignore-scripts=${DYNAMIC_POLICY}\n' >"$HOME/.npmrc"
  [ "$(_read_config_boolean "$HOME/.npmrc" ignore-scripts)" = unknown ]
}

@test "conflicting Yarn configurations do not pass" {
  mock_cli_script yarn $'#!/bin/bash\nexit 99'
  printf 'ignore-scripts true\n' >"$HOME/.yarnrc"
  printf 'enableScripts: true\n' >"$HOME/.yarnrc.yml"
  _check_package_script_policy yarn
  [ "$(_status_of supply.yarn.ignorescripts)" = skip ]
}

@test "policy reader refuses FIFOs without opening them" {
  mkfifo "$HOME/.npmrc"
  [ "$(_read_config_boolean "$HOME/.npmrc" ignore-scripts)" = unknown ]
}

@test "an unknown policy cannot hide known supply-chain gaps" {
  # Restrict this section test to policy and its composite. No external tool
  # needs to run, and no actual user configuration is read.
  _tool_path() { case "$1" in npm | yarn | pnpm) return 0 ;; *) return 1 ;; esac; }
  command() { return 1; }
  _check_supply_direnv() { :; }
  _check_supply_pip_extra_index() { :; }
  _check_supply_uv_config() { :; }
  printf 'ignore-scripts=false\n' >"$HOME/.npmrc"
  printf 'enableScripts: ${DYNAMIC_POLICY}\n' >"$HOME/.yarnrc.yml"
  section_13_supply_chain
  [ "$(_status_of supply.yarn.ignorescripts)" = skip ]
  [ "$(_status_of supply.posture)" = fail ]
}

@test "absent user settings do not assume unsafe version-specific defaults" {
  _tool_path() { return 0; }
  local manager
  for manager in npm yarn pnpm; do
    _check_package_script_policy "$manager"
    [ "$(_status_of "supply.$manager.ignorescripts")" = skip ]
  done
}

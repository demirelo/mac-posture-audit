#!/usr/bin/env bats

load '../helpers'

# Tests for the three v0.5 supply-chain helpers that section_13
# delegates to. Called directly so we don't have to mock npm/yarn/pnpm/
# brew/gh just to verify a HOME-relative file probe.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

# ─── supply.direnv.allow_list ─────────────────────────────────────────────

@test "direnv allow dir absent — skip (not in use)" {
  load_script
  isolate_home

  _check_supply_direnv

  assert_recorded skip "direnv not in use"
}

@test "direnv allow dir exists but empty — pass" {
  load_script
  isolate_home
  mkdir -p "$HOME/.local/share/direnv/allow"

  _check_supply_direnv

  assert_recorded pass "direnv allow list is empty"
}

@test "direnv allow dir with 3 entries — skip with count (informational)" {
  load_script
  isolate_home
  mkdir -p "$HOME/.local/share/direnv/allow"
  : >"$HOME/.local/share/direnv/allow/abc"
  : >"$HOME/.local/share/direnv/allow/def"
  : >"$HOME/.local/share/direnv/allow/ghi"

  _check_supply_direnv

  assert_recorded skip "3 direnv-approved .envrc path(s)"
}

@test "direnv allow dir with >20 entries — warns to prune" {
  load_script
  isolate_home
  mkdir -p "$HOME/.local/share/direnv/allow"
  for i in $(seq 1 25); do
    : >"$HOME/.local/share/direnv/allow/entry_$i"
  done

  _check_supply_direnv

  assert_recorded warn "25 direnv-approved .envrc path(s)"
}

# ─── supply.pip.extra_index_url ───────────────────────────────────────────

@test "no pip config anywhere — skip" {
  load_script
  isolate_home

  _check_supply_pip_extra_index

  assert_recorded skip "No pip config detected"
}

@test "pip config without extra-index-url — pass" {
  load_script
  isolate_home
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
[global]
timeout = 60
index-url = https://pypi.org/simple
CONF

  _check_supply_pip_extra_index

  assert_recorded pass "No pip extra-index-url configured"
}

@test "pip config with extra-index-url — warns" {
  load_script
  isolate_home
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
[global]
extra-index-url = https://internal-pypi.example.com/simple
CONF

  _check_supply_pip_extra_index

  assert_recorded warn "pip extra-index-url configured"
}

@test "pip extra-index-url — paranoid escalates to fail" {
  load_script
  isolate_home
  PROFILE="paranoid"
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
[global]
extra-index-url = https://internal.example.com/simple
CONF

  _check_supply_pip_extra_index

  assert_recorded fail "pip extra-index-url configured"
}

@test "pip extra-index-url — developer escalates to fail" {
  load_script
  isolate_home
  PROFILE="developer"
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
extra-index-url = https://example.com/simple
CONF

  _check_supply_pip_extra_index

  assert_recorded fail "pip extra-index-url configured"
}

@test "pip extra-index-url — founder escalates to fail" {
  load_script
  isolate_home
  PROFILE="founder"
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
extra-index-url = https://example.com/simple
CONF

  _check_supply_pip_extra_index

  assert_recorded fail "pip extra-index-url configured"
}

@test "pip extra-index-url path suppressed under --redact" {
  load_script
  isolate_home
  REDACT=true
  mkdir -p "$HOME/.config/pip"
  cat >"$HOME/.config/pip/pip.conf" <<'CONF'
extra-index-url = https://internal.example.com/simple
CONF

  _check_supply_pip_extra_index

  [[ "${RESULTS_WARN[*]}" != *"$HOME"* ]]
  [[ "${RESULTS_WARN[*]}" == *"1 location"* ]]
}

# ─── supply.uv.config ─────────────────────────────────────────────────────

@test "no uv/pixi config anywhere — skip" {
  load_script
  isolate_home

  _check_supply_uv_config

  assert_recorded skip "uv / pixi not configured"
}

@test "uv config without extra-index — pass" {
  load_script
  isolate_home
  mkdir -p "$HOME/.config/uv"
  cat >"$HOME/.config/uv/uv.toml" <<'CONF'
[pip]
index-url = "https://pypi.org/simple"
CONF

  _check_supply_uv_config

  assert_recorded pass "No uv / pixi extra-index-url configured"
}

@test "uv config with extra-index-url (kebab-case) — warns" {
  load_script
  isolate_home
  mkdir -p "$HOME/.config/uv"
  cat >"$HOME/.config/uv/uv.toml" <<'CONF'
extra-index-url = "https://internal.example.com/simple"
CONF

  _check_supply_uv_config

  assert_recorded warn "uv / pixi extra-index-url configured"
}

@test "pixi config with extra_index_urls (snake_case plural) — warns" {
  load_script
  isolate_home
  mkdir -p "$HOME/.config/pixi"
  cat >"$HOME/.config/pixi/config.toml" <<'CONF'
extra_index_urls = ["https://internal.example.com/simple"]
CONF

  _check_supply_uv_config

  assert_recorded warn "uv / pixi extra-index-url configured"
}

@test "uv extra-index — founder escalates to fail" {
  load_script
  isolate_home
  PROFILE="founder"
  mkdir -p "$HOME/.config/uv"
  cat >"$HOME/.config/uv/uv.toml" <<'CONF'
extra-index-url = "https://example.com/simple"
CONF

  _check_supply_uv_config

  assert_recorded fail "uv / pixi extra-index-url"
}

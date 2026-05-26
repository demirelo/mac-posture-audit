#!/usr/bin/env bats

load '../helpers'

# v1.6 §13 additions: registry credentials on disk (npm / PyPI), shell-rc
# webhook shapes, and the registry-credential composite. Each helper reads files
# under $HOME, so we isolate HOME to a tmpdir. Tokens/URLs must never surface.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

set_status() { STATUS_BY_ID="$STATUS_BY_ID $1=$2 "; }

# ── supply.npm_token.on_disk ───────────────────────────────────────────────

@test "npm token in ~/.npmrc — warns, token never printed" {
  load_script
  isolate_home
  printf '//registry.npmjs.org/:_authToken=npm_SUPERSECRETvalue\n' >"$HOME/.npmrc"
  _check_supply_npm_token
  assert_recorded warn "npm registry auth token stored in plaintext"
  local all="${RESULTS_PASS[*]:-} ${RESULTS_WARN[*]:-} ${RESULTS_FAIL[*]:-} ${RESULTS_SKIP[*]:-}"
  [[ "$all" != *"npm_SUPERSECRETvalue"* ]]
}

@test "npm registry without a token — passes" {
  load_script
  isolate_home
  printf 'registry=https://registry.npmjs.org/\nalways-auth=false\n' >"$HOME/.npmrc"
  _check_supply_npm_token
  assert_recorded pass "No plaintext npm registry token"
}

@test "no ~/.npmrc — npm_token skips" {
  load_script
  isolate_home
  _check_supply_npm_token
  assert_recorded skip "No ~/.npmrc to scan"
}

# ── supply.pypirc.credentials.on_disk ──────────────────────────────────────

@test "PyPI token in ~/.pypirc — warns, token never printed" {
  load_script
  isolate_home
  printf '[pypi]\nusername = __token__\npassword = pypi-AAAASECRETtoken\n' >"$HOME/.pypirc"
  _check_supply_pypirc_creds
  assert_recorded warn "PyPI upload credentials stored in plaintext"
  local all="${RESULTS_PASS[*]:-} ${RESULTS_WARN[*]:-} ${RESULTS_FAIL[*]:-} ${RESULTS_SKIP[*]:-}"
  [[ "$all" != *"pypi-AAAASECRETtoken"* ]]
}

@test "no ~/.pypirc — pypirc credentials skip" {
  load_script
  isolate_home
  _check_supply_pypirc_creds
  assert_recorded skip "No ~/.pypirc to scan"
}

# ── shell.webhook_destination ──────────────────────────────────────────────

@test "webhook in ~/.zshrc — warns, provider named, URL not printed" {
  load_script
  isolate_home
  printf 'curl -s https://hooks.slack.com/services/T00/B00/XXXXSECRET\n' >"$HOME/.zshrc"
  _check_shell_webhook
  assert_recorded warn "Webhook destination(s) referenced in"
  [[ "${RESULTS_WARN[*]}" == *"Slack"* ]]
  local all="${RESULTS_PASS[*]:-} ${RESULTS_WARN[*]:-} ${RESULTS_FAIL[*]:-} ${RESULTS_SKIP[*]:-}"
  [[ "$all" != *"XXXXSECRET"* ]]
  [[ "$all" != *"services/T00"* ]]
}

@test "clean shell rc files — shell webhook passes" {
  load_script
  isolate_home
  printf 'export PATH="$HOME/bin:$PATH"\n' >"$HOME/.zshrc"
  _check_shell_webhook
  assert_recorded pass "No webhook/exfil destinations referenced in shell rc"
}

# ── supply.registry_credentials.present (composite) ────────────────────────

@test "registry credentials composite warns when any cred row warns" {
  load_script
  set_status supply.npm_token.on_disk warn
  set_status supply.pypirc.credentials.on_disk skip
  set_status supply.cargo.creds skip
  set_status supply.gem.creds skip
  _check_supply_registry_credentials
  assert_recorded warn "Package-registry credentials present on disk"
}

@test "registry credentials composite passes when no cred row warns" {
  load_script
  set_status supply.npm_token.on_disk pass
  set_status supply.pypirc.credentials.on_disk skip
  set_status supply.cargo.creds skip
  set_status supply.gem.creds skip
  _check_supply_registry_credentials
  assert_recorded pass "No package-registry credentials detected on disk"
}

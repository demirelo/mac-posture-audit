#!/usr/bin/env bats

load '../helpers'

# v1.6 terminal composites: supply.blast_radius (additive amplifier score with a
# profile-aware fail threshold) and config.webhook_exfil_shape (aggregate of the
# per-area webhook rows + a direct ~/.npmrc / ~/.pypirc scan). Status-driven, so
# we seed STATUS_BY_ID and SANDBOX_FOUND directly.

set_status() { STATUS_BY_ID="$STATUS_BY_ID $1=$2 "; }

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

# A clean baseline for blast radius: sandbox present, outbound monitor running,
# nothing else flagged → score 0.
clean_base() {
  SANDBOX_FOUND=("Docker")
  set_status network.outboundmonitor.running pass
}

# ── supply.blast_radius ────────────────────────────────────────────────────

@test "blast_radius: clean baseline is low → pass" {
  load_script
  clean_base
  _check_supply_blast_radius
  assert_recorded pass "Supply-chain blast radius is low"
}

@test "blast_radius: one amplifier (lifecycle scripts) is elevated → warn under normal" {
  load_script
  clean_base
  set_status supply.npm.ignorescripts warn # +2
  _check_supply_blast_radius
  assert_recorded warn "Supply-chain blast radius is elevated"
}

@test "blast_radius: stacked amplifiers (>=5) are HIGH → fail under normal" {
  load_script
  clean_base
  set_status supply.npm.ignorescripts warn               # +2
  set_status ext.wallet warn                             # part of +2 ...
  set_status users.crypto_isolation_indicator warn       # ... wallet+weak iso = +2
  set_status supply.registry_credentials.present warn    # +2  => total 6
  _check_supply_blast_radius
  assert_recorded fail "Supply-chain blast radius is HIGH"
}

@test "blast_radius: founder fails one step sooner (score 4)" {
  load_script
  PROFILE="founder"
  clean_base
  set_status supply.npm.ignorescripts warn               # +2
  set_status ext.wallet warn                             # +2 (with iso) ...
  set_status users.crypto_isolation_indicator warn       # ... = score 4
  _check_supply_blast_radius
  assert_recorded fail "Supply-chain blast radius is HIGH"
}

@test "blast_radius: same score 4 is only elevated (warn) under normal" {
  load_script
  clean_base
  set_status supply.npm.ignorescripts warn
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  _check_supply_blast_radius
  assert_recorded warn "Supply-chain blast radius is elevated"
}

@test "blast_radius: no score number is shown in the label" {
  load_script
  clean_base
  set_status supply.npm.ignorescripts warn
  _check_supply_blast_radius
  # Internal score must not leak as a digit in the row.
  [[ "${RESULTS_WARN[*]}" != *"score"* ]]
  [[ ! "${RESULTS_WARN[*]}" =~ \(.*[0-9].*\) ]]
}

# ── config.webhook_exfil_shape ─────────────────────────────────────────────

@test "config_webhook: warns when a per-area webhook row warns" {
  load_script
  isolate_home
  set_status mcp.servers.webhook_destination warn
  _check_config_webhook_shape
  assert_recorded warn "Webhook/exfil-shaped destination(s) in config surface(s)"
  [[ "${RESULTS_WARN[*]}" == *"MCP configs"* ]]
}

@test "config_webhook: passes when nothing references a webhook" {
  load_script
  isolate_home
  set_status mcp.servers.webhook_destination pass
  set_status shell.webhook_destination pass
  set_status persistence.launchagent.webhook_destination pass
  set_status agent.instructions.webhook_destination pass
  _check_config_webhook_shape
  assert_recorded pass "No webhook/exfil-shaped destinations in scanned config surfaces"
}

@test "config_webhook: catches a webhook in ~/.npmrc directly, no URL leak" {
  load_script
  isolate_home
  printf '//registry.npmjs.org/:_authToken=x\nfoo=https://webhook.site/abcd-SECRET\n' >"$HOME/.npmrc"
  _check_config_webhook_shape
  assert_recorded warn "config surface(s)"
  [[ "${RESULTS_WARN[*]}" == *".npmrc"* ]]
  [[ "${RESULTS_WARN[*]}" != *"abcd-SECRET"* ]]
}

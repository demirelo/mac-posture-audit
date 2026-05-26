#!/usr/bin/env bats

load '../helpers'

# Section 29 — named attack-chain composites (_check_attack_chains). Each reads
# constituent statuses via _status_of and sandbox presence via SANDBOX_FOUND.
# We populate both directly (far easier than orchestrating eight sections).

set_status() {
  STATUS_BY_ID="$STATUS_BY_ID $1=$2 "
}

# ── chain.fake_interview ──────────────────────────────────────────────────

@test "fake_interview: IDE trust loose + no sandbox — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status ide.vscode.workspace_trust fail
  _check_attack_chains
  assert_recorded warn "Fake-interview chain"
}

@test "fake_interview: automatic tasks on + no sandbox — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status ide.cursor.automatic_tasks warn
  _check_attack_chains
  assert_recorded warn "Fake-interview chain"
}

@test "fake_interview: founder profile escalates to fail" {
  load_script
  PROFILE="founder"
  SANDBOX_FOUND=()
  set_status ide.vscode.automatic_tasks warn
  _check_attack_chains
  assert_recorded fail "Fake-interview chain"
}

@test "fake_interview: sandbox available defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=("Docker")
  set_status ide.vscode.workspace_trust fail
  _check_attack_chains
  assert_recorded skip "Fake-interview chain not present"
}

@test "fake_interview: IDE trust intact — skip even without a sandbox" {
  load_script
  SANDBOX_FOUND=()
  set_status ide.vscode.workspace_trust pass
  set_status ide.cursor.workspace_trust pass
  _check_attack_chains
  assert_recorded skip "Fake-interview chain not present"
}

# ── chain.wallet_drain ────────────────────────────────────────────────────

@test "wallet_drain: wallet + no isolation + no outbound monitor — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  set_status network.outboundmonitor.running warn
  _check_attack_chains
  assert_recorded warn "Wallet-drain chain"
}

@test "wallet_drain: outbound monitor present defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=()
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  set_status network.outboundmonitor.running pass
  _check_attack_chains
  assert_recorded skip "Wallet-drain chain not present"
}

@test "wallet_drain: healthy isolation defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=()
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator pass
  set_status network.outboundmonitor.running warn
  _check_attack_chains
  assert_recorded skip "Wallet-drain chain not present"
}

# ── chain.agent_exposure ──────────────────────────────────────────────────

@test "agent_exposure: filesystem-capable MCP + wallet — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status mcp.servers.filesystem_capable warn
  set_status ext.wallet warn
  _check_attack_chains
  assert_recorded warn "Agent-exposure chain"
}

@test "agent_exposure: remote MCP + wallet — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status mcp.servers.remote_http warn
  set_status ext.wallet warn
  _check_attack_chains
  assert_recorded warn "Agent-exposure chain"
}

@test "agent_exposure: web3 profile escalates to fail" {
  load_script
  PROFILE="web3"
  SANDBOX_FOUND=()
  set_status mcp.servers.filesystem_capable warn
  set_status ext.wallet warn
  _check_attack_chains
  assert_recorded fail "Agent-exposure chain"
}

@test "agent_exposure: no wallet defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=()
  set_status mcp.servers.remote_http warn
  set_status ext.wallet pass
  _check_attack_chains
  assert_recorded skip "Agent-exposure chain not present"
}

# ── chain.cloud_exfil ─────────────────────────────────────────────────────

@test "cloud_exfil: a sensitive dir under cloud sync — warns" {
  load_script
  SANDBOX_FOUND=()
  set_status data.ssh.cloud_sync_exposure fail
  _check_attack_chains
  assert_recorded warn "Cloud-exfil chain"
}

@test "cloud_exfil: founder profile escalates to fail" {
  load_script
  PROFILE="founder"
  SANDBOX_FOUND=()
  set_status data.dotfiles.cloud_sync_exposure warn
  _check_attack_chains
  assert_recorded fail "Cloud-exfil chain"
}

@test "cloud_exfil: nothing under cloud sync — skip" {
  load_script
  SANDBOX_FOUND=()
  set_status data.ssh.cloud_sync_exposure pass
  set_status data.crypto.cloud_sync_exposure skip
  set_status data.dotfiles.cloud_sync_exposure pass
  _check_attack_chains
  assert_recorded skip "Cloud-exfil chain not present"
}

# ── chain.supply_to_wallet (v1.6) ──────────────────────────────────────────

@test "supply_to_wallet: wallet + weak iso + lifecycle scripts + no sandbox — warns" {
  load_script
  SANDBOX_FOUND=() # containment gap
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  set_status supply.npm.ignorescripts warn # install-time exec path
  _check_attack_chains
  assert_recorded warn "Supply-to-wallet chain"
}

@test "supply_to_wallet: healthy isolation defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=()
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator pass
  set_status supply.npm.ignorescripts warn
  _check_attack_chains
  assert_recorded skip "Supply-to-wallet chain not present"
}

@test "supply_to_wallet: sandbox + outbound monitor close the containment gap (skip)" {
  load_script
  SANDBOX_FOUND=("Docker")
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  set_status supply.npm.ignorescripts warn
  set_status network.outboundmonitor.running pass
  _check_attack_chains
  assert_recorded skip "Supply-to-wallet chain not present"
}

@test "supply_to_wallet: web3 profile escalates to fail (IDE autorun as the exec path)" {
  load_script
  PROFILE="web3"
  SANDBOX_FOUND=()
  set_status ext.wallet warn
  set_status users.crypto_isolation_indicator warn
  set_status ide.vscode.automatic_tasks warn
  _check_attack_chains
  assert_recorded fail "Supply-to-wallet chain"
}

# ── chain.agent_supply_chain (v1.6) ────────────────────────────────────────

@test "agent_supply_chain: agent files + suspicious directive + SSH keys — warns" {
  load_script
  SANDBOX_FOUND=()
  AGENT_FILES_FOUND=3 # surface
  set_status agent.instructions.suspicious_directives warn # agent-exec risk
  set_status ssh.keys.unencrypted warn                     # valuable target
  _check_attack_chains
  assert_recorded warn "Agent-supply-chain chain"
}

@test "agent_supply_chain: fs-capable MCP surface + registry creds — warns" {
  load_script
  SANDBOX_FOUND=()
  AGENT_FILES_FOUND=0
  set_status mcp.servers.filesystem_capable warn      # surface AND risk
  set_status supply.registry_credentials.present warn # target
  _check_attack_chains
  assert_recorded warn "Agent-supply-chain chain"
}

@test "agent_supply_chain: no valuable target defuses the chain (skip)" {
  load_script
  SANDBOX_FOUND=()
  AGENT_FILES_FOUND=3
  set_status agent.instructions.suspicious_directives warn
  _check_attack_chains
  assert_recorded skip "Agent-supply-chain chain not present"
}

@test "agent_supply_chain: developer profile escalates to fail" {
  load_script
  PROFILE="developer"
  SANDBOX_FOUND=()
  set_status mcp.servers.filesystem_capable warn
  set_status ext.wallet warn
  _check_attack_chains
  assert_recorded fail "Agent-supply-chain chain"
}

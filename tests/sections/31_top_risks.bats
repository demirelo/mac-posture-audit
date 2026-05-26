#!/usr/bin/env bats

load '../helpers'

# Tests for the v1.3 decision layer: action-priority tiering (_tier_of),
# the executive verdict + "Top risks to address" renderer (emit_decision_layer),
# and the HIGH_BLAST_IDS / LOW_TIER_IDS id-resolution guard.

# add_rank ID STATUS "label" — append a rankable row the way _record would.
add_rank() {
  RANK_ID+=("$1")
  RANK_STATUS+=("$2")
  RANK_LABEL+=("$3")
  RANK_HINT+=("")
  STATUS_BY_ID="$STATUS_BY_ID$1=$2 "
  case "$2" in
  warn) WARN_N=$((WARN_N + 1)) ;;
  fail) FAIL_N=$((FAIL_N + 1)) ;;
  esac
}

# ── _tier_of ────────────────────────────────────────────────────────────────

@test "_tier_of: ordinary fail under normal is high, not urgent" {
  load_script
  run _tier_of system.filevault.on fail
  [ "$output" = "high" ]
}

@test "_tier_of: high-blast fail is urgent" {
  load_script
  run _tier_of ext.wallet fail
  [ "$output" = "urgent" ]
}

@test "_tier_of: chain.* fail is urgent (glob match)" {
  load_script
  run _tier_of chain.agent_exposure fail
  [ "$output" = "urgent" ]
}

@test "_tier_of: ide.*.workspace_trust fail is urgent (glob match)" {
  load_script
  run _tier_of ide.vscode.workspace_trust fail
  [ "$output" = "urgent" ]
}

@test "_tier_of: ordinary warn under normal is medium" {
  load_script
  run _tier_of network.bluetooth.off warn
  [ "$output" = "medium" ]
}

@test "_tier_of: hygiene warn is low" {
  load_script
  run _tier_of network.firewall.blockall warn
  [ "$output" = "low" ]
}

@test "_tier_of: profile-escalated warn becomes high under that profile" {
  load_script
  # supply.npm.ignorescripts is ordinary (medium) under normal …
  run _tier_of supply.npm.ignorescripts warn
  [ "$output" = "medium" ]
  # … but founder escalates it, so it is profile-relevant -> high.
  PROFILE="founder"
  run _tier_of supply.npm.ignorescripts warn
  [ "$output" = "high" ]
}

@test "_tier_of: pass/skip are not tiered" {
  load_script
  run _tier_of system.sip.enabled pass
  [ -z "$output" ]
  run _tier_of network.dns.resolvers skip
  [ -z "$output" ]
}

# ── emit_decision_layer ───────────────────────────────────────────────────────

@test "verdict: clean baseline is calm, no panic, Action priority none" {
  load_script
  PASS_N=90
  run emit_decision_layer
  [[ "$output" == *"Executive Verdict"* ]]
  [[ "$output" == *"Strong baseline: 90 pass, 0 fail."* ]]
  [[ "$output" == *"No outstanding risks for the normal profile."* ]]
  [[ "$output" == *"Action priority: none"* ]]
  [[ "$output" != *"Top risks to address"* ]]
  [[ "$output" != *"URGENT"* ]]
}

@test "verdict: founder + wallet warn surfaces control-plane concentration" {
  load_script
  PASS_N=82
  PROFILE="founder"
  add_rank ext.wallet warn "Wallet extension(s) installed: MetaMask"
  run emit_decision_layer
  [[ "$output" == *"control-plane concentration"* ]]
  [[ "$output" == *"Action priority: high"* ]]
}

@test "top risks: tiers ordered urgent > high > medium > low" {
  load_script
  PROFILE="web3"
  add_rank network.firewall.blockall warn "App Firewall not in block-all mode" # low
  add_rank network.bluetooth.off warn "Bluetooth is on"                        # medium
  add_rank chain.agent_exposure fail "Agent can reach secrets + wallet"        # urgent
  add_rank backup.recovery_path fail "No backup configured"                    # high
  run emit_decision_layer
  # Expected printed order: urgent(1) high(2) medium(3) low(4)
  local u h m l
  u=$(printf '%s\n' "$output" | grep -n '\[urgent ' | cut -d: -f1)
  h=$(printf '%s\n' "$output" | grep -n '\[high ' | cut -d: -f1)
  m=$(printf '%s\n' "$output" | grep -n '\[medium ' | cut -d: -f1)
  l=$(printf '%s\n' "$output" | grep -n '\[low ' | cut -d: -f1)
  [ "$u" -lt "$h" ]
  [ "$h" -lt "$m" ]
  [ "$m" -lt "$l" ]
}

@test "top risks: --top N caps the list but keeps the verdict" {
  load_script
  TOP_N=2
  add_rank ext.wallet fail "Wallet a"
  add_rank ssh.keys.unencrypted fail "Key b"
  add_rank system.theft_resistance fail "Theft c"
  run emit_decision_layer
  [[ "$output" == *"Top risks to address"* ]]
  [ "$(printf '%s\n' "$output" | grep -cE '^  [0-9]+\. ')" -eq 2 ]
}

@test "top risks: --top 0 hides the list but still prints the verdict" {
  load_script
  TOP_N=0
  add_rank ext.wallet fail "Wallet a"
  run emit_decision_layer
  [[ "$output" == *"Executive Verdict"* ]]
  [[ "$output" == *"Action priority: urgent"* ]]
  [[ "$output" != *"Top risks to address"* ]]
}

# ── Golden output fixture (one, shape + key phrases, not exact counts) ─────────

@test "golden: founder report shape (verdict + action priority + tiered risk)" {
  load_script
  PASS_N=82
  PROFILE="founder"
  add_rank ext.wallet warn "Wallet extension(s) installed: MetaMask → Brave"
  add_rank backup.recovery_path warn "Backup recovery path: iCloud Drive sync only — PARTIAL"
  run emit_decision_layer
  [[ "$output" == *"━━━ Executive Verdict ━━━"* ]]
  [[ "$output" == *"Profile: founder"* ]]
  [[ "$output" == *"Action priority:"* ]]
  [[ "$output" == *"Top risks to address:"* ]]
  [[ "$output" == *"[high · "*"effort] Wallet extension(s) installed"* ]]
}

# ── JSON surfacing helpers ────────────────────────────────────────────────────

@test "_compute_tiers tallies counts and sets overall priority" {
  load_script
  PROFILE="web3"
  add_rank chain.agent_exposure fail "agent reaches secrets + wallet" # urgent
  add_rank backup.recovery_path fail "no backup"                      # high
  add_rank network.bluetooth.off warn "bluetooth on"                  # medium
  add_rank network.firewall.blockall warn "firewall"                  # low
  _compute_tiers
  [ "$TIER_URGENT_N" -eq 1 ]
  [ "$TIER_HIGH_N" -eq 1 ]
  [ "$TIER_MEDIUM_N" -eq 1 ]
  [ "$TIER_LOW_N" -eq 1 ]
  [ "$OVERALL_PRIORITY" = "urgent" ]
}

@test "_build_top_risks_json emits ranked, tier-ordered objects" {
  load_script
  PROFILE="web3"
  add_rank network.bluetooth.off warn "bluetooth on" # medium
  add_rank ext.wallet fail "wallet extension"        # urgent
  run _build_top_risks_json
  python3 - "$output" <<'PY'
import json, sys
a = json.loads("[" + sys.argv[1] + "]")
assert [x["rank"] for x in a] == [1, 2], a
assert a[0]["tier"] == "urgent" and a[0]["id"] == "ext.wallet", a
assert a[1]["tier"] == "medium", a
PY
}

@test "_build_top_risks_json is empty under --top 0" {
  load_script
  TOP_N=0
  add_rank ext.wallet fail "wallet extension"
  run _build_top_risks_json
  [ -z "$output" ]
}

# ── remediation effort (v1.5) ─────────────────────────────────────────────────

@test "_effort_of: structural fixes are high, setting flips are low, rest medium" {
  load_script
  run _effort_of ext.wallet
  [ "$output" = "high" ]
  run _effort_of users.crypto_isolation_indicator
  [ "$output" = "high" ]
  run _effort_of network.firewall.blockall
  [ "$output" = "low" ]
  run _effort_of ide.vscode.automatic_tasks
  [ "$output" = "low" ]
  run _effort_of network.listening.all_interfaces
  [ "$output" = "medium" ]
}

@test "_build_top_risks_json carries an effort field per entry" {
  load_script
  add_rank ext.wallet fail "wallet"
  run _build_top_risks_json
  python3 - "$output" <<'PY'
import json
import sys
a = json.loads("[" + sys.argv[1] + "]")
assert a[0]["effort"] == "high", a
PY
}

# ── ID-resolution guard ───────────────────────────────────────────────────────

@test "every literal HIGH_BLAST_IDS / LOW_TIER_IDS entry resolves to a known id" {
  load_script
  local ids_file="$REPO_ROOT/tests/fixtures/expected_ids.txt"
  local entry
  for entry in $HIGH_BLAST_IDS $LOW_TIER_IDS; do
    # Skip glob patterns (documented; matched at runtime, not literal ids).
    case "$entry" in *'*'*) continue ;; esac
    grep -qxF "$entry" "$ids_file" || {
      printf 'HIGH_BLAST_IDS/LOW_TIER_IDS entry not in expected_ids.txt: %s\n' "$entry" >&2
      return 1
    }
  done
}

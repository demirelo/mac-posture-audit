#!/usr/bin/env bats

# End-to-end smoke that --redact does not embed identifying values in the
# JSON output. These tests run the full script against a real macOS host
# and then grep the produced JSON for known-leaky tokens. They assert
# absence — if a future contributor adds a new check that bypasses
# `redact`, the relevant test fails with the offending line.

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  OUT="$BATS_TEST_TMPDIR/posture.json"
}

run_redacted() {
  cd "$REPO_ROOT"
  # The script exits 1 whenever any FAIL row was emitted (e.g. on a stock
  # GitHub macos-latest runner with FileVault off). That is the script's
  # normal "I found problems" signal, not a runtime error — bats' set -e
  # would otherwise fail the test before any assertion ran.
  ./mac-posture-audit.sh --json --quick --redact > "$OUT" || true
  [[ -s "$OUT" ]]
}

@test "--redact does not embed the real hostname" {
  run_redacted
  ! grep -qF "\"host\":\"$(hostname)\"" "$OUT"
}

@test "--redact does not embed the user's home path" {
  run_redacted
  # $HOME literal must not appear in any label or hint.
  ! grep -qF "$HOME" "$OUT"
}

@test "--redact does not embed Time Machine destination names" {
  run_redacted
  # Common destination name tokens. None of these should ever appear
  # under --redact; the row collapses to "Time Machine destination
  # configured" without the name.
  body=$(cat "$OUT")
  for token in "Time Machine destination configured: "; do
    [[ "$body" != *"$token"* ]] || {
      echo "leaked: $token" >&2
      return 1
    }
  done
}

@test "--redact does not embed VPN process names in network.vpn.running" {
  run_redacted
  # `network.vpn.running` should emit "VPN client running" without
  # appending a process list. If the row is present, it must not
  # contain a colon-prefixed list.
  vpn_row=$(grep -o '{[^}]*"network\.vpn\.running"[^}]*}' "$OUT" || true)
  if [[ -n "$vpn_row" ]]; then
    [[ "$vpn_row" != *'VPN client running: '* ]]
  fi
}

@test "--redact does not embed system extension bundle IDs" {
  run_redacted
  # If network.systemextensions.active is present, its label must not
  # contain "(s):" followed by a bundle ID list.
  se_row=$(grep -o '{[^}]*"network\.systemextensions\.active"[^}]*}' "$OUT" || true)
  if [[ -n "$se_row" ]]; then
    [[ "$se_row" != *'system extension(s): '* ]]
  fi
}

@test "--redact does not embed AV brand names in av.engine.detected" {
  run_redacted
  av_row=$(grep -o '{[^}]*"av\.engine\.detected"[^}]*}' "$OUT" || true)
  if [[ -n "$av_row" ]]; then
    # Brand-suppressed labels are "Two AV/EDR engines detected" or
    # "AV/EDR running (1 engine)" — neither contains a colon-name.
    [[ "$av_row" != *'AV/EDR running: '* ]]
    [[ "$av_row" != *'AV/EDR engines: '* ]]
  fi
}

@test "--redact does not embed brew tap names" {
  run_redacted
  tap_row=$(grep -o '{[^}]*"supply\.brew\.taps"[^}]*}' "$OUT" || true)
  if [[ -n "$tap_row" ]]; then
    [[ "$tap_row" != *'Third-party Homebrew taps: '* ]]
  fi
}

@test "--redact does not embed wallet extension brand names" {
  run_redacted
  wallet_row=$(grep -o '{[^}]*"ext\.wallet"[^}]*}' "$OUT" || true)
  if [[ -n "$wallet_row" ]]; then
    # Under --redact the label is "N wallet extension(s) installed".
    [[ "$wallet_row" != *'Wallet extension(s) installed: '* ]]
  fi
}

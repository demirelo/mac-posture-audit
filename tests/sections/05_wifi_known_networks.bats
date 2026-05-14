#!/usr/bin/env bats

load '../helpers'

# Tests for _check_wifi_known_networks. Called directly via the helper
# so we don't have to mock the rest of section_05's AirDrop + Bluetooth
# probes for every test case.

setup_wifi_sandbox() {
  WIFI_FIXTURE_DIR="$BATS_TEST_TMPDIR/wifi"
  mkdir -p "$WIFI_FIXTURE_DIR"
  WIFI_KNOWN_PLISTS=("$WIFI_FIXTURE_DIR/known-networks.plist")
  export WIFI_KNOWN_PLISTS
}

# Write a plist (xml1 format — plutil -p reads xml plists fine and
# emits the bracketed dump our SSID counter regexes against).
write_wifi_plist() {
  local body="$1"
  cat >"${WIFI_KNOWN_PLISTS[0]}" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyLists-1.0.dtd">
<plist version="1.0">
${body}
</plist>
XML
}

# Convenience: emit N entries that match one of the SSID regex variants.
emit_ssid_entries() {
  local count="$1" i body=""
  body="<dict>"
  for i in $(seq 1 "$count"); do
    body+="<key>wifi.network.ssid.NET_$i</key>"
    body+="<dict><key>name</key><string>net_$i</string></dict>"
  done
  body+="</dict>"
  printf '%s' "$body"
}

@test "no wifi plist found — skip" {
  load_script
  WIFI_KNOWN_PLISTS=("$BATS_TEST_TMPDIR/does-not-exist.plist")
  export WIFI_KNOWN_PLISTS

  _check_wifi_known_networks

  assert_recorded skip "Wi-Fi known networks plist not found"
}

@test "plist with 0 SSIDs (no matching keys) — skip with parse-fail hint" {
  load_script
  setup_wifi_sandbox
  write_wifi_plist '<dict><key>not_an_ssid</key><string>x</string></dict>'

  _check_wifi_known_networks

  assert_recorded skip "count not parsable"
}

@test "plist with 5 SSIDs — pass (within reasonable history)" {
  load_script
  setup_wifi_sandbox
  write_wifi_plist "$(emit_ssid_entries 5)"

  _check_wifi_known_networks

  assert_recorded pass "Wi-Fi known networks: 5"
}

@test "plist with 30 SSIDs — pass (at threshold)" {
  load_script
  setup_wifi_sandbox
  write_wifi_plist "$(emit_ssid_entries 30)"

  _check_wifi_known_networks

  assert_recorded pass "Wi-Fi known networks: 30"
}

@test "plist with 31 SSIDs — warn (over threshold)" {
  load_script
  setup_wifi_sandbox
  write_wifi_plist "$(emit_ssid_entries 31)"

  _check_wifi_known_networks

  assert_recorded warn "31 remembered"
}

@test "plist with 75 SSIDs — warn with prune nudge" {
  load_script
  setup_wifi_sandbox
  write_wifi_plist "$(emit_ssid_entries 75)"

  _check_wifi_known_networks

  assert_recorded warn "75 remembered"
}

@test "plist with both modern + legacy SSID keys — not double-counted" {
  # Regression for the v1.0.0 bug where the SSID count regex matched
  # both modern (wifi.network.ssid.*) and legacy (SSIDString) keys in
  # one pass. A plist with 5 modern entries that also includes nested
  # SSIDString compatibility fields would emit count=10, making 20
  # real networks look like 40. The fix probes modern first and only
  # falls back to legacy if the modern count is zero.
  load_script
  setup_wifi_sandbox
  # 5 modern entries, each also carrying a nested SSIDString field.
  cat >"${WIFI_KNOWN_PLISTS[0]}" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyLists-1.0.dtd">
<plist version="1.0">
<dict>
  <key>wifi.network.ssid.NET_1</key>
  <dict><key>SSIDString</key><string>net_1</string></dict>
  <key>wifi.network.ssid.NET_2</key>
  <dict><key>SSIDString</key><string>net_2</string></dict>
  <key>wifi.network.ssid.NET_3</key>
  <dict><key>SSIDString</key><string>net_3</string></dict>
  <key>wifi.network.ssid.NET_4</key>
  <dict><key>SSIDString</key><string>net_4</string></dict>
  <key>wifi.network.ssid.NET_5</key>
  <dict><key>SSIDString</key><string>net_5</string></dict>
</dict>
</plist>
XML

  _check_wifi_known_networks

  assert_recorded pass "Wi-Fi known networks: 5"
  # The buggy regex would have produced 10; fail the test if we see it.
  [[ "${RESULTS_PASS[*]}" != *"10 "* ]]
}

@test "plist with only legacy keys (no modern) — counted via fallback" {
  load_script
  setup_wifi_sandbox
  cat >"${WIFI_KNOWN_PLISTS[0]}" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyLists-1.0.dtd">
<plist version="1.0">
<array>
  <dict><key>SSIDString</key><string>legacy_1</string></dict>
  <dict><key>SSIDString</key><string>legacy_2</string></dict>
  <dict><key>SSIDString</key><string>legacy_3</string></dict>
</array>
</plist>
XML

  _check_wifi_known_networks

  assert_recorded pass "Wi-Fi known networks: 3"
}

#!/usr/bin/env bats

load '../helpers'

# Tests for _check_browser_extensions_inventory (v1.2.0).
#
# Hermetic via BROWSER_EXT_CHROMIUM_ROOTS / BROWSER_EXT_FIREFOX_ROOTS — the
# helper accepts pipe-delimited "<brand>|<root>" entries, so we point both
# arrays at fixture trees under $BATS_TEST_TMPDIR.

isolate_home_and_roots() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
  CHROME_ROOT="$ISOLATED_HOME/chrome"
  FIREFOX_ROOT="$ISOLATED_HOME/firefox"
  BROWSER_EXT_CHROMIUM_ROOTS=("Chrome|$CHROME_ROOT" "Brave|$ISOLATED_HOME/brave")
  BROWSER_EXT_FIREFOX_ROOTS=("Firefox|$FIREFOX_ROOT")
}

write_chromium_ext() {
  # write_chromium_ext <brand_root> <profile> <ext_id> <version> [manifest_body]
  local root="$1" profile="$2" ext_id="$3" version="$4" body="${5:-{\"name\":\"x\",\"version\":\"$4\"\}}"
  local dir="$root/$profile/Extensions/$ext_id/$version"
  mkdir -p "$dir"
  printf '%s' "$body" >"$dir/manifest.json"
}

write_firefox_ext() {
  # write_firefox_ext <profile_dir> <addon_id>
  local prof="$1" addon="$2"
  mkdir -p "$prof"
  cat >"$prof/extensions.json" <<EOF
{
  "schemaVersion": 33,
  "addons": [
    {"id":"$addon","version":"1.0","type":"extension","active":true},
    {"id":"theme-not-counted@mozilla.org","version":"1.0","type":"theme","active":true}
  ]
}
EOF
}

write_catalog() {
  local path="$1"
  shift
  : >"$path"
  for line in "$@"; do
    printf '%s\n' "$line" >>"$path"
  done
  EXPOSURE_CATALOG_PATH="$path"
  load_exposure_catalog
}

@test "no browsers — both rows emit skip" {
  load_script
  isolate_home_and_roots

  _check_browser_extensions_inventory

  assert_recorded skip "No browser extensions found"
  assert_recorded skip "No exposure catalog loaded"
}

@test "single Chromium extension — count=1, suspicious skips (no catalog)" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "1.0"

  _check_browser_extensions_inventory

  assert_recorded skip "Browser extensions detected: 1"
  assert_recorded skip "No exposure catalog loaded"
}

@test "Chromium extension matched by catalog at severity=critical — fail" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "drainerextidaaaaaaaaaaaaaaaaaaaa" "1.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "browser_extension_id|drainerextidaaaaaaaaaaaaaaaaaaaa|critical|drainer-test-1"

  _check_browser_extensions_inventory

  assert_recorded fail "Catalog-matched browser extensions"
  assert_recorded fail "drainerextidaaaaaaaaaaaaaaaaaaaa"
}

@test "Chromium extension matched at severity=warn — warn (not fail)" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "warnableextidaaaaaaaaaaaaaaaaaaaa" "1.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "browser_extension_id|warnableextidaaaaaaaaaaaaaaaaaaaa|warn|advisory-1"

  _check_browser_extensions_inventory

  assert_recorded warn "Catalog-matched browser extensions"
  [[ "${RESULTS_FAIL[*]:-}" != *"Catalog-matched browser extensions"* ]]
}

@test "Firefox addon counted via extensions.json (theme entries ignored)" {
  load_script
  isolate_home_and_roots
  write_firefox_ext "$FIREFOX_ROOT/profile.default" "ublock0@raymondhill.net"

  _check_browser_extensions_inventory

  assert_recorded skip "Browser extensions detected: 1"
}

@test "Chromium + Firefox combined — total counts both" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "1.0"
  write_firefox_ext "$FIREFOX_ROOT/profile.default" "ublock0@raymondhill.net"

  _check_browser_extensions_inventory

  assert_recorded skip "Browser extensions detected: 2"
}

@test "multi-profile install of the same Chromium ext counted once" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "dupextidaaaaaaaaaaaaaaaaaaaaaaaa" "1.0"
  write_chromium_ext "$CHROME_ROOT" "Profile 1" "dupextidaaaaaaaaaaaaaaaaaaaaaaaa" "1.0"

  _check_browser_extensions_inventory

  assert_recorded skip "Browser extensions detected: 1"
}

@test "--redact suppresses extension IDs in suspicious label" {
  load_script
  isolate_home_and_roots
  REDACT=true
  write_chromium_ext "$CHROME_ROOT" "Default" "drainerextidaaaaaaaaaaaaaaaaaaaa" "1.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "browser_extension_id|drainerextidaaaaaaaaaaaaaaaaaaaa|critical|drainer-test-1"

  _check_browser_extensions_inventory

  assert_recorded fail "1 browser extension(s) match exposure catalog"
  [[ "${RESULTS_FAIL[*]:-}" != *"drainerextidaaaaaaaaaaaaaaaaaaaa"* ]]
}

@test "catalog match where ID is not installed produces no suspicious row" {
  load_script
  isolate_home_and_roots
  write_chromium_ext "$CHROME_ROOT" "Default" "innocentextidaaaaaaaaaaaaaaaaaaa" "1.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "browser_extension_id|differentextidaaaaaaaaaaaaaaaaaa|critical|drainer-test-1"

  _check_browser_extensions_inventory

  assert_recorded pass "No catalog-matched suspicious browser extensions"
}

@test "Chromium extension dir without manifest.json is skipped (Temp dirs)" {
  load_script
  isolate_home_and_roots
  # Create an Extensions/<id>/ entry but no version subdir with manifest.
  mkdir -p "$CHROME_ROOT/Default/Extensions/halfinstalledextidaaaaaaaaaaaaaaaa"

  _check_browser_extensions_inventory

  assert_recorded skip "No browser extensions found"
}

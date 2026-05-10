#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  MODE="json"
}

@test "_json_escape escapes the JSON control character set" {
  result=$(_json_escape $'a\\b"c\nd\re\tf\bg\fh')
  [ "$result" = 'a\\b\"c\nd\re\tf\bg\fh' ]
}

@test "label and hint with newlines, tabs, quotes, and backslashes round-trip through JSON" {
  warn $'multi\nline\tlabel with "quote" and \\back' $'hint\nspans\tlines'
  [ "${#JSON_ROWS[@]}" -eq 1 ]
  python3 - "${JSON_ROWS[0]}" <<'PY'
import json, sys
row = json.loads(sys.argv[1])
assert row["status"] == "warn", row
assert row["label"] == 'multi\nline\tlabel with "quote" and \\back', row["label"]
assert row["hint"] == "hint\nspans\tlines", row["hint"]
PY
}

@test "fully assembled JSON document with control-character labels still parses" {
  pass $'one\ntwo'
  warn $'a\tb' $'hint\\with\\backslash'
  fail "trail" "trail-hint"
  body=$(IFS=,; printf '%s' "${JSON_ROWS[*]}")
  doc="{\"summary\":{\"pass\":${PASS_N},\"warn\":${WARN_N},\"fail\":${FAIL_N},\"skip\":${SKIP_N}},\"results\":[${body}]}"
  python3 - "$doc" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
labels = [r["label"] for r in d["results"]]
assert labels[0] == "one\ntwo", labels[0]
assert labels[1] == "a\tb", labels[1]
assert d["results"][1]["hint"] == "hint\\with\\backslash", d["results"][1]["hint"]
PY
}

@test "top-level host/macos/arch fields round-trip through _json_escape" {
  # Hostnames in practice don't contain " or \, but the JSON producer must
  # not assume that. The row-level _record path was already going through
  # _json_escape; the top-level emit_summary path now does too. Smoke-test
  # by feeding edge-character values through _json_escape directly (the
  # actual emit_summary captures hostname output, which we can't easily
  # mock without forking the whole script).
  mac=$(_json_escape 'macOS "26.0" \beta')
  arch=$(_json_escape $'arm64\n')
  host=$(_json_escape 'host"with\backslash')
  doc="{\"host\":\"$host\",\"macos\":\"$mac\",\"arch\":\"$arch\",\"summary\":{\"pass\":0,\"warn\":0,\"fail\":0,\"skip\":0},\"results\":[]}"
  python3 - "$doc" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["host"] == 'host"with\\backslash', d["host"]
assert d["macos"] == 'macOS "26.0" \\beta', d["macos"]
assert d["arch"] == 'arm64\n', d["arch"]
PY
}

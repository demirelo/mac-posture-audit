#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-mac-posture-audit.sh}"

if [[ ! -f "$TARGET" ]]; then
  echo "read-only check: missing target script: $TARGET" >&2
  exit 2
fi

failures=0

report_hits() {
  local title="$1" hits="$2"
  if [[ -n "$hits" ]]; then
    printf '\n%s\n%s\n' "$title" "$hits" >&2
    failures=$((failures + 1))
  fi
}

# These regexes intentionally look for commands in command position rather than
# words inside remediation hints. They are a tripwire, not a shell parser.
command_prefix='(^|[;&|({]|then|do|else)[[:space:]]*'
optional_sudo='(sudo[[:space:]]+(-n[[:space:]]+)?)?'

mutating_single_commands='(rm|rmdir|mv|cp|install|chmod|chown|chgrp|touch|tee|truncate|dd|mkfs|diskutil|hdiutil|kill|killall|pkill|osascript|sqlite3)'
mutating_single_re="${command_prefix}${optional_sudo}${mutating_single_commands}([[:space:];|&)]|$)"

mutating_multi_re="${command_prefix}${optional_sudo}(defaults[[:space:]]+(write|delete)|plutil[[:space:]]+(-replace|-insert|-remove)|launchctl[[:space:]]+(load|unload|bootstrap|bootout|kickstart|enable|disable)|profiles[[:space:]]+(-R|remove|delete|install|renew|sync)|systemsetup[[:space:]]+-set|spctl[[:space:]]+--master|dseditgroup[[:space:]]+|fdesetup[[:space:]]+(enable|disable|changerecovery|removerecovery)|tmutil[[:space:]]+(startbackup|enable|disable|delete|setdestination|removedestination)|brew[[:space:]]+(install|upgrade|uninstall|tap|untap)|npm[[:space:]]+(install|update|uninstall)|pip3?[[:space:]]+install|curl[^|]*[|][[:space:]]*(sh|bash)|wget[^|]*[|][[:space:]]*(sh|bash))([[:space:];|&)]|$)"

# Read-only allowlist for binaries that double as read-only inspectors when
# called with the right flag/syntax. Each entry strips lines from the
# command-position match that satisfy the read-only contract.
#   sqlite3   — must pass -readonly as the first sqlite3 argument.
#   osascript — must match the exact read-only login-item query used by §22.
# These operate on `grep -n` output, so `:` is included as a command boundary.
readonly_sqlite3_re='([;&|({:]|then|do|else)[[:space:]]*(sudo[[:space:]]+(-n[[:space:]]+)?)?sqlite3[[:space:]]+-readonly([[:space:]\\]|$)'
readonly_osascript_re="osascript[[:space:]]+-e[[:space:]]+'tell application \"System Events\" to get the name of every login item'[[:space:]]*(2?>|\\|\\||&&|\\)|;|$)"
# `brew tap` with no name argument lists installed taps (read-only). Allowlist
# only that listing form — `brew tap NAME` (installs a third-party tap) stays
# rejected. The pattern matches `brew tap` followed immediately by a redirect
# (`2>`, `>`), a logical operator (`||`, `&&`), a closing `)`, or end-of-line.
readonly_brew_tap_re='brew[[:space:]]+tap[[:space:]]*(2?>|\|\||&&|\)|;|$)'

network_re="${command_prefix}(curl|wget|nc|ncat|telnet|ssh|scp|sftp|ftp|gh)([[:space:];|&)]|$)"
report_line_re='^[0-9]+:[[:space:]]*(pass|warn|fail|skip|_record)[[:space:]]'

single_hits=$(grep -En "$mutating_single_re" "$TARGET" | grep -Ev "$report_line_re" || true)
# Strip read-only-allowlisted invocations (sqlite3 -readonly, get-style osascript).
if [[ -n "$single_hits" ]]; then
  single_hits=$(printf '%s\n' "$single_hits" | grep -Ev "$readonly_sqlite3_re" | grep -Ev "$readonly_osascript_re" || true)
fi
multi_hits=$(grep -En "$mutating_multi_re" "$TARGET" | grep -Ev "$report_line_re" || true)
if [[ -n "$multi_hits" ]]; then
  multi_hits=$(printf '%s\n' "$multi_hits" | grep -Ev "$readonly_brew_tap_re" || true)
fi
network_hits=$(grep -En "$network_re" "$TARGET" | grep -Ev "$report_line_re" | grep -Ev 'test.nextdns.io|gh[[:space:]]+auth[[:space:]]+status' || true)

report_hits "Potential mutating command invocation(s):" "$single_hits"
report_hits "Potential mutating multi-word command invocation(s):" "$multi_hits"
report_hits "Unexpected network command invocation(s):" "$network_hits"

if grep -Eq "${command_prefix}curl([[:space:];|&)]|$)" "$TARGET"; then
  if ! grep -q 'test.nextdns.io' "$TARGET"; then
    echo "curl is present but the allowed NextDNS endpoint is missing." >&2
    failures=$((failures + 1))
  fi
  if ! grep -q 'if \$NETWORK; then' "$TARGET"; then
    echo "curl is present but the NETWORK opt-in guard was not found." >&2
    failures=$((failures + 1))
  fi
fi

if grep -Eq "${command_prefix}gh[[:space:]]+auth[[:space:]]+status([[:space:];|&)]|$)" "$TARGET"; then
  if ! grep -q 'if \$NETWORK; then' "$TARGET"; then
    echo "gh auth status is present but the NETWORK opt-in guard was not found." >&2
    failures=$((failures + 1))
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  cat >&2 <<'MSG'

Read-only safety check failed.
If a flagged command is truly read-only, tighten this checker with a narrow
allowlist and explain the exception in the README.
MSG
  exit 1
fi

echo "read-only safety check passed for $TARGET"

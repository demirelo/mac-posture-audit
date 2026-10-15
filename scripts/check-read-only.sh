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
command_prefix='(^|[;&|({]|then[[:space:]]|do[[:space:]]|else[[:space:]])[[:space:]]*'
# Catch ordinary wrappers and absolute paths. This remains a static tripwire,
# not a proof about arbitrary shell evaluation or dynamically built commands.
command_wrappers='((command|exec|env)[[:space:]]+|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+[[:space:]]+)*'
binary_path='(/[A-Za-z0-9_.-]+)*/'
optional_sudo='((/usr/bin/)?sudo[[:space:]]+(-n[[:space:]]+)?)?'
invocation_prefix="${command_prefix}${command_wrappers}${optional_sudo}${command_wrappers}(${binary_path})?"

mutating_single_commands='(rm|rmdir|mv|cp|install|chmod|chown|chgrp|touch|tee|truncate|dd|mkfs|diskutil|hdiutil|kill|killall|pkill|osascript|sqlite3)'
mutating_single_re="${invocation_prefix}${mutating_single_commands}([[:space:];|&)]|$)"

mutating_multi_re="${invocation_prefix}(defaults[[:space:]]+(write|delete)|plutil[[:space:]]+(-replace|-insert|-remove)|launchctl[[:space:]]+(load|unload|bootstrap|bootout|kickstart|enable|disable)|profiles[[:space:]]+(-R|remove|delete|install|renew|sync)|systemsetup[[:space:]]+-set|spctl[[:space:]]+--master|dseditgroup[[:space:]]+|fdesetup[[:space:]]+(enable|disable|changerecovery|removerecovery)|tmutil[[:space:]]+(startbackup|enable|disable|delete|setdestination|removedestination)|brew[[:space:]]+(install|upgrade|uninstall|tap|untap)|npm[[:space:]]+(install|update|uninstall)|pip3?[[:space:]]+install|curl[^|]*[|][[:space:]]*(sh|bash)|wget[^|]*[|][[:space:]]*(sh|bash))([[:space:];|&)]|$)"

# Replace only an approved command token, never its whole source line. A second
# command on the same line must still be inspected. The terminator matters for
# osascript and brew: extra arguments change their behaviour.
readonly_sqlite3_re="(${invocation_prefix})sqlite3[[:space:]]+-readonly[[:space:]]+-init[[:space:]]+/dev/null([[:space:]]|$)"
readonly_osascript_re="(${invocation_prefix})osascript[[:space:]]+-e[[:space:]]+'tell application \"System Events\" to get the name of every login item'[[:space:]]*(2?>|\\|\\||&&|\\)|;|$)"
readonly_brew_tap_re="(${invocation_prefix})brew[[:space:]]+tap[[:space:]]*(2?>|\\|\\||&&|\\)|;|$)"
readonly_curl_re="(${invocation_prefix})curl[[:space:]]+-q[[:space:]]+-sS[[:space:]]+--max-time[[:space:]]+5[[:space:]]+--proto[[:space:]]+'=https'[[:space:]]+https://test[.]nextdns[.]io[[:space:]]*(2?>|\\|\\||&&|\\)|;|$)"
readonly_gh_re="(${invocation_prefix})gh[[:space:]]+auth[[:space:]]+status[[:space:]]*(2?>|\\|\\||&&|\\)|;|$)"
network_re="${invocation_prefix}(curl|wget|nc|ncat|telnet|ssh|scp|sftp|ftp|gh)([[:space:];|&)]|$)"

# Keep remediation strings out of the command-position scan, but never ignore
# a reporter with executable substitution or commands after its final argument.
# Reporter rows in the audit consist exclusively of quoted arguments.
report_line_re='^[[:space:]]*(pass|warn|fail|skip|_record)[[:space:]]+"[^"]*"([[:space:]]+"[^"]*")*[[:space:]]*$'
# Fold explicit line continuations before matching; keep blank lines so later
# diagnostics retain their original source line numbers.
source=$(awk '
  !pending && /^[[:space:]]*#/ { print ""; next }
  {
    line = $0
    slashes = 0
    for (i = length(line); i > 0 && substr(line, i, 1) == "\\"; i--) slashes++
    if (slashes % 2) {
      sub(/\\$/, "", line)
      pending = pending line " "
      blanks++
      next
    }
    print pending line
    pending = ""
    while (blanks > 0) { print ""; blanks-- }
  }
  END { if (pending != "") print pending }
' "$TARGET")
source=$(printf '%s\n' "$source" | awk -v reports="$report_line_re" '
  $0 ~ reports && $0 !~ /\$\(|`/ { print ""; next }
  { print }
')

# sqlite3 -readonly stops database writes, but not CLI commands or extension
# loading. These spellings have no place in the narrow TCC query exception.
sqlite_source=$(printf '%s\n' "$source" | sed -E 's@-init[[:space:]]+/dev/null([[:space:]]|$)@__empty_init\1@g')
sqlite_unsafe=$(printf '%s\n' "$sqlite_source" | grep -Ein "sqlite3.*(\\.(shell|system|output|once|read|open|load|backup|save|log|clone|excel|archive|testcase|import)|load_extension|writefile|ATTACH|-[[:space:]]*(cmd|init))" || true)
report_hits "Unsafe sqlite3 CLI or SQL operation(s):" "$sqlite_unsafe"

# Replace the matched invocation, not all occurrences of its command name.
# Semicolons retain command boundaries for the remaining text after replacement.
normalised=$(printf '%s\n' "$source" |
  sed -E "s@${readonly_sqlite3_re}@; __approved; @g" |
  sed -E "s@${readonly_osascript_re}@; __approved; @g" |
  sed -E "s@${readonly_brew_tap_re}@; __approved; @g")

single_hits=$(printf '%s\n' "$normalised" | grep -En "$mutating_single_re" || true)
multi_hits=$(printf '%s\n' "$normalised" | grep -En "$mutating_multi_re" || true)
report_hits "Potential mutating command invocation(s):" "$single_hits"
report_hits "Potential mutating multi-word command invocation(s):" "$multi_hits"

# Network exceptions must be INSIDE the true arm of an explicit NETWORK guard.
# Track nested if blocks and close the exception on else/elif. A guard elsewhere
# in the file or in a comment must never authorise a network command.
network_source=$(printf '%s\n' "$source" | awk '
  /^[[:space:]]*if[[:space:]].*;[[:space:]]*then([[:space:]]|$)/ {
    depth++
    guard[depth] = ($0 ~ /^[[:space:]]*if \$NETWORK; then[[:space:]]*$/)
  }
  /^[[:space:]]*(else|elif)([[:space:];]|$)/ { guard[depth] = 0 }
  {
    active = 0
    for (i = 1; i <= depth; i++) active += guard[i]
    # Prefix each line with its guard state; source text cannot forge it.
    print (active ? "1:" : "0:") $0
  }
  /^[[:space:]]*fi([[:space:];]|$)/ || /;[[:space:]]*fi[[:space:]]*$/ {
    delete guard[depth]
    if (depth > 0) depth--
  }
')
network_source=$(printf '%s\n' "$network_source" |
  sed -E "/^1:/ { s/^1://; s@${readonly_curl_re}@; __approved; @g; s@${readonly_gh_re}@; __approved; @g; }; s/^0://")
network_hits=$(printf '%s\n' "$network_source" | grep -En "$network_re" || true)
report_hits "Unexpected or unguarded network command invocation(s):" "$network_hits"

if [[ "$failures" -gt 0 ]]; then
  cat >&2 <<'MSG'

Read-only safety check failed.
If a flagged command is truly read-only, tighten this checker with a narrow
allowlist and explain the exception in the README.
MSG
  exit 1
fi

echo "read-only safety check passed for $TARGET"

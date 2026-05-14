#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# macOS Posture Audit
#
# What it does:  Runs ~100 read-only checks against your Mac's security config
#                and prints a colored report with remediation hints.
# What it isn't: It does not change anything on your system. Safe to run.
# Who it's for:  Anyone on a personal Mac. No assumptions about your folder
#                layout, your name, your email, or your existing apps.
#
# Usage:
#   ./mac-posture-audit.sh
#   sudo ./mac-posture-audit.sh          # fuller audit; still read-only
#   ./mac-posture-audit.sh --quick       # skip checks that require sudo
#   ./mac-posture-audit.sh --network     # opt in to live network probes
#   ./mac-posture-audit.sh --json        # machine-readable output
#
# Section flow (top to bottom):
#   System integrity → Login → Privacy/Lockdown → Network (firewall/AirDrop/
#   DNS/proxies) → AV → Browsers → Browser extensions → SSH → Git signing →
#   Supply chain → Password mgr / 2FA → Crypto hardware wallet → Folder
#   layout → Backups → iCloud → User accounts → Updates & Find My →
#   Persistence & TCC.
#
# Exit code: 0 if no FAILs, 1 if any FAIL, 2 if script error.
# ─────────────────────────────────────────────────────────────────────────────

# SC2088 is suppressed for user-facing display/remediation strings that mention
# literal tilde paths such as ~/.ssh/config without relying on shell expansion.
# shellcheck disable=SC2088
set -uo pipefail

SCRIPT_VERSION="1.1.0"

# ── State ───────────────────────────────────────────────────────────────────
PASS_N=0
WARN_N=0
FAIL_N=0
SKIP_N=0
declare -a RESULTS_PASS RESULTS_WARN RESULTS_FAIL RESULTS_SKIP
declare -a JSON_ROWS

# ── Args ────────────────────────────────────────────────────────────────────
parse_args() {
  # MODE controls output format: "full" (terminal) or "json".
  # QUICK / NETWORK / REDACT are independent booleans — combine freely.
  MODE="full"
  QUICK=false      # --quick: skip sudo-required checks
  NETWORK=false    # --network: allow external probes (default off)
  REDACT=false     # --redact: mask host/email/usernames/IPs/paths in output
  PROFILE="normal" # --profile: severity calibration (normal|web3|paranoid|developer|founder)
  DIFF_PATH=""     # --diff: compare current run against previous JSON
  expect_profile=false
  expect_diff=false
  for arg in "$@"; do
    if $expect_profile; then
      case "$arg" in
      normal | web3 | paranoid | developer | founder) PROFILE="$arg" ;;
      *)
        echo "unknown profile: $arg (one of: normal, web3, paranoid, developer, founder)"
        exit 2
        ;;
      esac
      expect_profile=false
      continue
    fi
    if $expect_diff; then
      if [[ -z "$arg" ]]; then
        echo "--diff requires a path to a previous JSON output"
        exit 2
      fi
      DIFF_PATH="$arg"
      expect_diff=false
      continue
    fi
    case "$arg" in
    --quick) QUICK=true ;;
    --json) MODE="json" ;;
    --network) NETWORK=true ;;
    --offline) NETWORK=false ;;
    --redact) REDACT=true ;;
    --profile) expect_profile=true ;;
    --profile=*)
      arg="${arg#--profile=}"
      case "$arg" in
      normal | web3 | paranoid | developer | founder) PROFILE="$arg" ;;
      *)
        echo "unknown profile: $arg (one of: normal, web3, paranoid, developer, founder)"
        exit 2
        ;;
      esac
      ;;
    --diff) expect_diff=true ;;
    --diff=*)
      DIFF_PATH="${arg#--diff=}"
      if [[ -z "$DIFF_PATH" ]]; then
        echo "--diff requires a path to a previous JSON output"
        exit 2
      fi
      ;;
    --version)
      printf 'mac-posture-audit %s\n' "$SCRIPT_VERSION"
      exit 0
      ;;
    -h | --help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
      cat <<'USAGE'

Flags (combinable):
  --quick           Skip checks that require sudo
  --json            Machine-readable JSON output
  --network         Allow live external probes (e.g., test.nextdns.io). Default off.
  --offline         Force no external calls (default).
  --redact          Mask hostname, email addresses, admin usernames, resolver IPs,
                    and $HOME paths in output. Use this when sharing the report.
  --profile NAME    Severity profile. One of: normal (default), web3, paranoid,
                    developer, founder. Escalates specific checks based on
                    threat model (e.g. wallet-on-main-user is warn under
                    normal, fail under web3 / paranoid). The 'founder'
                    profile is the union of developer + web3 escalations
                    for solo founders shipping their own code who also
                    custody crypto.
  --diff PATH       Compare current run against a previously saved
                    --json output. Prints one line per id whose status
                    differs. Implies --json (run is collected internally).
  --version         Show version and exit.
  --help            Show this help text and exit.
USAGE
      exit 0
      ;;
    *)
      echo "unknown arg: $arg (try --help)"
      exit 2
      ;;
    esac
  done
  if $expect_profile; then
    echo "--profile requires a value (one of: normal, web3, paranoid, developer, founder)"
    exit 2
  fi
  if $expect_diff; then
    echo "--diff requires a path to a previous JSON output"
    exit 2
  fi

  # --diff implies json collection; we need rows in JSON_ROWS to compare.
  if [[ -n "$DIFF_PATH" ]]; then
    if [[ ! -r "$DIFF_PATH" ]]; then
      echo "--diff: cannot read $DIFF_PATH"
      exit 2
    fi
    MODE="json"
  fi

}

detect_runtime() {
  # When launched via sudo, keep auditing the invoking user's home directory.
  # Otherwise user-level checks would inspect /var/root instead of the real account.
  if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    SUDO_USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory:[[:space:]]*//' | head -1)
    [[ -d "$SUDO_USER_HOME" ]] && HOME="$SUDO_USER_HOME"
  fi

  ARCH=$(uname -m)
  IS_APPLE_SILICON=false
  [[ "$ARCH" == "arm64" ]] && IS_APPLE_SILICON=true
  MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")

}

init_colors() {
  # ── Colors (auto-disable if not a TTY) ──────────────────────────────────────
  if [[ -t 1 ]] && [[ "$MODE" != "json" ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    DIM=$'\033[2m'
    BOLD=$'\033[1m'
    NC=$'\033[0m'
  else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    DIM=""
    BOLD=""
    NC=""
  fi

}

# ── Output helpers ──────────────────────────────────────────────────────────
section() {
  [[ "$MODE" == "json" ]] && return
  echo
  printf "%s━━━ %s ━━━%s\n" "$BOLD$BLUE" "$1" "$NC"
}

# Severity profiles — escalate specific checks based on threat model.
# Each entry: "profile|id|from_status|to_status".
# A check whose default status equals from_status is rewritten to to_status
# when the active profile matches. `normal` has no entries (the default).
# Bash 3.2 has no associative arrays; lookup is linear (~25 entries × ~70 ids).
PROFILE_OVERRIDES=(
  # web3 — wallet user; supply chain is the primary attacker surface.
  "web3|ext.wallet|warn|fail"
  "web3|supply.npm.ignorescripts|warn|fail"
  "web3|supply.yarn.ignorescripts|warn|fail"
  "web3|supply.pnpm.ignorescripts|warn|fail"
  "web3|supply.scanner|warn|fail"
  "web3|ssh.keys.unencrypted|warn|fail"
  "web3|ext.simulator.advice|warn|fail"
  "web3|data.crypto.cloud_sync_exposure|warn|fail"
  "web3|apps.remote_access.present|warn|fail"
  "web3|users.crypto_isolation_indicator|warn|fail"
  "web3|ide.vscode.workspace_trust|warn|fail"
  "web3|ide.cursor.workspace_trust|warn|fail"
  "web3|browser.version_currency|warn|fail"
  "web3|network.vpn.killswitch|warn|fail"
  "web3|browser.remote_debugging|warn|fail"
  "web3|browser.password_autofill|skip|warn"
  # paranoid — high-threat user; lock down everything.
  "paranoid|ext.wallet|warn|fail"
  "paranoid|supply.npm.ignorescripts|warn|fail"
  "paranoid|supply.yarn.ignorescripts|warn|fail"
  "paranoid|supply.pnpm.ignorescripts|warn|fail"
  "paranoid|supply.scanner|warn|fail"
  "paranoid|ssh.keys.unencrypted|warn|fail"
  "paranoid|network.bluetooth.off|warn|fail"
  "paranoid|network.airdrop.discoverable|warn|fail"
  "paranoid|network.firewall.blockall|warn|fail"
  "paranoid|network.firewall.stealth|warn|fail"
  "paranoid|backup.tm.recency|warn|fail"
  "paranoid|backup.tm.encrypted|warn|fail"
  "paranoid|data.crypto.cloud_sync_exposure|warn|fail"
  "paranoid|apps.remote_access.present|warn|fail"
  "paranoid|users.crypto_isolation_indicator|warn|fail"
  "paranoid|ide.vscode.workspace_trust|warn|fail"
  "paranoid|ide.cursor.workspace_trust|warn|fail"
  "paranoid|browser.version_currency|warn|fail"
  "paranoid|network.vpn.killswitch|warn|fail"
  "paranoid|update.auto|warn|fail"
  "paranoid|cred.docker.auth|warn|fail"
  "paranoid|supply.pip.extra_index_url|warn|fail"
  "paranoid|supply.uv.config|warn|fail"
  "paranoid|network.listening.all_interfaces|warn|fail"
  "paranoid|ssh.config.risky_options|warn|fail"
  "paranoid|browser.remote_debugging|warn|fail"
  "paranoid|browser.password_autofill|skip|warn"
  "paranoid|update.macos.recency|warn|fail"
  # developer — supply chain matters; wallet-warn keeps default semantic.
  # cred.shellrc.patterns is intentionally absent: it already emits as `fail`
  # for every profile (the patterns are high-confidence prefixed tokens —
  # AKIA[0-9A-Z]{16}, ghp_…{36,}, sk-ant-…, etc. — and plaintext API keys in
  # a shell rc are P0 regardless of profile).
  "developer|supply.npm.ignorescripts|warn|fail"
  "developer|supply.yarn.ignorescripts|warn|fail"
  "developer|supply.pnpm.ignorescripts|warn|fail"
  "developer|supply.scanner|warn|fail"
  "developer|supply.pip.extra_index_url|warn|fail"
  "developer|supply.uv.config|warn|fail"
  "developer|network.listening.all_interfaces|warn|fail"
  "developer|ssh.config.risky_options|warn|fail"
  # founder — union of developer + web3. Solo founders who ship their own
  # code AND custody crypto have both attack surfaces. The list mirrors
  # the developer and web3 entries above; if either of those changes,
  # update here too. Keeping the entries explicit (rather than computed)
  # keeps the override table greppable and the bash 3.2 lookup simple.
  "founder|ext.wallet|warn|fail"
  "founder|supply.npm.ignorescripts|warn|fail"
  "founder|supply.yarn.ignorescripts|warn|fail"
  "founder|supply.pnpm.ignorescripts|warn|fail"
  "founder|supply.scanner|warn|fail"
  "founder|supply.pip.extra_index_url|warn|fail"
  "founder|supply.uv.config|warn|fail"
  "founder|ssh.keys.unencrypted|warn|fail"
  "founder|ext.simulator.advice|warn|fail"
  "founder|data.crypto.cloud_sync_exposure|warn|fail"
  "founder|apps.remote_access.present|warn|fail"
  "founder|users.crypto_isolation_indicator|warn|fail"
  "founder|ide.vscode.workspace_trust|warn|fail"
  "founder|ide.cursor.workspace_trust|warn|fail"
  "founder|browser.version_currency|warn|fail"
  "founder|network.vpn.killswitch|warn|fail"
  "founder|network.listening.all_interfaces|warn|fail"
  "founder|ssh.config.risky_options|warn|fail"
  "founder|browser.remote_debugging|warn|fail"
  "founder|browser.password_autofill|skip|warn"
)

# Apply the profile severity table to a (status, id) pair. Returns the
# possibly-rewritten status on stdout.
_apply_profile() {
  local status="$1" id="$2"
  if [[ -z "$id" || "${PROFILE:-normal}" == "normal" ]]; then
    printf '%s' "$status"
    return
  fi
  local prefix="${PROFILE}|${id}|${status}|"
  local entry
  for entry in "${PROFILE_OVERRIDES[@]}"; do
    if [[ "$entry" == "$prefix"* ]]; then
      printf '%s' "${entry##*|}"
      return
    fi
  done
  printf '%s' "$status"
}

# Escape a string for embedding inside a JSON string literal. Backslash must be
# replaced first or later substitutions will double-escape. Covers the JSON
# control-character set so any defaults/plutil/etc. value pulled into a label
# or hint round-trips through json.loads().
_json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//$'\b'/\\b}
  s=${s//$'\f'/\\f}
  printf '%s' "$s"
}

# _proc_running PATTERN — returns 0 if any process matches PATTERN against
# its full argv (-f). pgrep on macOS uses ERE; do NOT use BRE alternation
# (`\|` would be treated as a literal). Pass an ERE alternation like
# 'foo|bar' instead. Without -f, pgrep matches only against the truncated
# kinfo p_comm, which misses launchd-spawned daemons whose binary path
# differs from the brand name (CrowdStrike's falcond, MDE's wdavdaemon, …).
_proc_running() { pgrep -qfi -- "$1" 2>/dev/null; }

# _arr_contains NEEDLE [HAYSTACK ARGS...] — true if NEEDLE is among the
# remaining arguments. Bash 3.2 safe; tolerates an empty haystack without
# the `${arr[@]:-}` trap (which iterates once over the empty string).
_arr_contains() {
  local needle="$1"
  shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

# Tracks every id emitted by _record so collisions are caught at the
# emitter, not after JSON assembly. Bash 3.2: keep as a space-delimited
# string of " id1 id2 …" so we can substring-match.
EMITTED_IDS=" "

# Parallel id→status map for composite checks that need to read the
# outcome of earlier rows (backup.recovery_path, system.theft_resistance,
# ssh.posture, supply.posture, 2fa.fido_gap). Stored as space-delimited
# `id=status` entries so a Bash 3.2 lookup is a one-line `case` over the
# string.
STATUS_BY_ID=""

# _status_of ID — returns the status emitted for ID (pass/warn/fail/skip),
# or empty if the id has not been emitted yet. Composite checks must run
# AFTER the rows they depend on.
_status_of() {
  local id="$1" entry
  for entry in $STATUS_BY_ID; do
    if [[ "$entry" == "$id="* ]]; then
      printf '%s' "${entry#*=}"
      return
    fi
  done
  printf ''
}

_record() {
  # _record STATUS "label" "hint" "id"
  # id is optional and identifies a logical check uniquely within a single run.
  # Stable across runs so external consumers can diff successive scans by id.
  local status="$1" label="$2" hint="${3:-}" id="${4:-}"

  # Reject duplicate ids early. A typo'd or copy-pasted id would otherwise
  # show up only in the post-hoc JSON validator with a confusing site.
  if [[ -n "$id" && "$EMITTED_IDS" == *" $id "* ]]; then
    printf 'mac-posture-audit: duplicate check id "%s" (label: %s)\n' "$id" "$label" >&2
    exit 2
  fi
  [[ -n "$id" ]] && EMITTED_IDS="$EMITTED_IDS$id "

  # Apply --profile severity override before counters/output.
  status=$(_apply_profile "$status" "$id")

  # Track id→status AFTER profile override so composites see what the
  # report actually showed.
  [[ -n "$id" ]] && STATUS_BY_ID="$STATUS_BY_ID$id=$status "

  # 1. Always increment counters first — JSON mode used to skip these.
  case "$status" in
  pass)
    PASS_N=$((PASS_N + 1))
    RESULTS_PASS+=("$label")
    ;;
  warn)
    WARN_N=$((WARN_N + 1))
    RESULTS_WARN+=("$label — $hint")
    ;;
  fail)
    FAIL_N=$((FAIL_N + 1))
    RESULTS_FAIL+=("$label — $hint")
    ;;
  skip)
    SKIP_N=$((SKIP_N + 1))
    RESULTS_SKIP+=("$label")
    ;;
  esac

  # 2. JSON branch: emit row, return. Counters are already updated above.
  if [[ "$MODE" == "json" ]]; then
    local elabel ehint eid
    elabel=$(_json_escape "$label")
    ehint=$(_json_escape "$hint")
    eid=$(_json_escape "$id")
    JSON_ROWS+=("{\"id\":\"$eid\",\"status\":\"$status\",\"label\":\"$elabel\",\"hint\":\"$ehint\"}")
    return
  fi

  # 3. Terminal rendering
  case "$status" in
  pass) printf "  %s✅ PASS%s %s\n" "$GREEN" "$NC" "$label" ;;
  warn)
    printf "  %s⚠️  WARN%s %s\n" "$YELLOW" "$NC" "$label"
    [[ -n "$hint" ]] && printf "          %s%s%s\n" "$DIM" "$hint" "$NC"
    ;;
  fail)
    printf "  %s❌ FAIL%s %s\n" "$RED" "$NC" "$label"
    [[ -n "$hint" ]] && printf "          %s%s%s\n" "$DIM" "$hint" "$NC"
    ;;
  skip)
    printf "  %s⏭  SKIP%s %s\n" "$DIM" "$NC" "$label"
    [[ -n "$hint" ]] && printf "          %s%s%s\n" "$DIM" "$hint" "$NC"
    ;;
  esac
}
# Reporter wrappers: pass/skip take LABEL [ID]; warn/fail take LABEL HINT [ID].
# Backward-compatible — passing no ID emits an empty id, which the validator
# rejects (so coverage stays honest as new check sites are added).
pass() { _record pass "$1" "" "${2:-}"; }
warn() { _record warn "$1" "${2:-}" "${3:-}"; }
fail() { _record fail "$1" "${2:-}" "${3:-}"; }
skip() { _record skip "$1" "${2:-}" "${3:-}"; }

# ── Redaction helper ────────────────────────────────────────────────────────
# Usage:  redact host   "$value"
#         redact email  "$value"
#         redact user   "$value"
#         redact ip     "$value"
#         redact path   "$value"
# When $REDACT is true, returns a placeholder; otherwise echoes the value.
redact() {
  local kind="$1" value="${2:-}"
  if [[ "$REDACT" != "true" ]]; then
    printf '%s' "$value"
    return
  fi
  case "$kind" in
  host) printf '<HOST>' ;;
  email) printf '<EMAIL>' ;;
  user) printf '<USER>' ;;
  ip) printf '<IP>' ;;
  path) printf '%s' "${value//$HOME/~}" ;;
  *) printf '%s' "$value" ;;
  esac
}

# Helper to redact a comma-separated list of IPs or usernames
redact_list() {
  local kind="$1" list="$2" out=""
  if [[ "$REDACT" != "true" ]]; then
    printf '%s' "$list"
    return
  fi
  local IFS=','
  for item in $list; do
    [[ -n "$out" ]] && out="$out,"
    out="${out}$(redact "$kind" "$item")"
  done
  printf '%s' "$out"
}

# ── Cloud-sync root detection ───────────────────────────────────────────────
# _path_in_cloud_root PATH — prints the cloud provider name if PATH (after
# tilde + $HOME expansion) is inside a known sync root; empty string otherwise.
#
# Detected providers:
#   - iCloud Drive       (~/Library/Mobile Documents/com~apple~CloudDocs)
#   - Dropbox            (~/Library/CloudStorage/Dropbox or ~/Dropbox)
#   - Google Drive       (~/Library/CloudStorage/GoogleDrive* or ~/Google Drive)
#   - OneDrive           (~/Library/CloudStorage/OneDrive* or ~/OneDrive)
#   - Box                (~/Library/CloudStorage/Box* or ~/Box Sync)
#   - generic File Provider (~/Library/CloudStorage/* fallback — covers Sync,
#                            pCloud, MEGA, etc.)
#
# Caller is responsible for tilde + env expansion before invoking. This
# function does NOT resolve symlinks (no fork) — a symlink that points INTO
# a cloud root but is itself outside it will be missed. Documented limit.
_path_in_cloud_root() {
  local p="$1"
  case "$p" in
  *"Library/Mobile Documents/com~apple~CloudDocs"*) printf 'iCloud Drive' ;;
  *"Library/CloudStorage/Dropbox"* | "$HOME/Dropbox"*) printf 'Dropbox' ;;
  *"Library/CloudStorage/GoogleDrive"* | "$HOME/Google Drive"*) printf 'Google Drive' ;;
  *"Library/CloudStorage/OneDrive"* | "$HOME/OneDrive"*) printf 'OneDrive' ;;
  *"Library/CloudStorage/Box"* | "$HOME/Box Sync"*) printf 'Box' ;;
  *"Library/CloudStorage/"*) printf 'Cloud (File Provider)' ;;
  *) printf '' ;;
  esac
}

_tcc_query_approved() {
  # _tcc_query_approved DB USE_SUDO
  # Prints "service|client" rows for approved TCC grants. Supports both the
  # modern auth_value schema and the older allowed schema. Returns non-zero if
  # the database cannot be read or the schema is not recognised.
  local db="$1" use_sudo="$2" cols query
  if [[ "$use_sudo" == "true" ]]; then
    sudo -n test -r "$db" 2>/dev/null || return 1
    cols=$(sudo -n sqlite3 -readonly "$db" "PRAGMA table_info(access);" 2>/dev/null) || return 1
  else
    [[ -r "$db" ]] || return 1
    cols=$(sqlite3 -readonly "$db" "PRAGMA table_info(access);" 2>/dev/null) || return 1
  fi

  if echo "$cols" | grep -q '|auth_value|'; then
    query="SELECT service || '|' || client FROM access WHERE auth_value=2 ORDER BY service, client"
  elif echo "$cols" | grep -q '|allowed|'; then
    query="SELECT service || '|' || client FROM access WHERE allowed=1 ORDER BY service, client"
  else
    return 1
  fi

  if [[ "$use_sudo" == "true" ]]; then
    sudo -n sqlite3 -readonly "$db" "$query" 2>/dev/null || return 1
  else
    sqlite3 -readonly "$db" "$query" 2>/dev/null || return 1
  fi
}

# ── Browser-extension detection helpers (used by AV + Browser Extensions) ──
detect_ext_in_chromium() {
  # $1 = extension ID; prints space-separated browser names where found.
  local id="$1"
  local found=()
  local roots=(
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
    "$HOME/Library/Application Support/Google/Chrome"
    "$HOME/Library/Application Support/Microsoft Edge"
    "$HOME/Library/Application Support/Arc/User Data"
    "$HOME/Library/Application Support/Vivaldi"
  )
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    for prof in "$root"/Default "$root"/Profile*; do
      [[ -d "$prof/Extensions/$id" ]] && {
        found+=("$(basename "$root")")
        break
      }
    done
  done
  echo "${found[*]:-}"
}

detect_ext_by_name() {
  # $1 = case-insensitive substring/regex matched against extension name fields.
  # Checks both manifest.json AND _locales/*/messages.json — many extensions use
  # "name": "__MSG_extName__" placeholders that resolve via locale files.
  local name_pat="$1"
  local found=()
  local roots=(
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
    "$HOME/Library/Application Support/Google/Chrome"
    "$HOME/Library/Application Support/Microsoft Edge"
    "$HOME/Library/Application Support/Arc/User Data"
    "$HOME/Library/Application Support/Vivaldi"
  )
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    local hit=false
    for prof in "$root"/Default "$root"/Profile*; do
      [[ -d "$prof/Extensions" ]] || continue
      for extdir in "$prof/Extensions"/*/; do
        for vdir in "$extdir"*/; do
          local manifest="${vdir}manifest.json"
          [[ -f "$manifest" ]] || continue
          # 1. Direct match in manifest.json
          if grep -qiE "\"(name|short_name|default_title)\"[[:space:]]*:[[:space:]]*\"[^\"]*${name_pat}[^\"]*\"" "$manifest" 2>/dev/null; then
            hit=true
            break
          fi
          # 2. Internationalized name — check English/default locale messages.json files
          for msgfile in "${vdir}_locales/en"*/messages.json "${vdir}_locales/_default/messages.json"; do
            [[ -f "$msgfile" ]] || continue
            if grep -qiE "\"message\"[[:space:]]*:[[:space:]]*\"[^\"]*${name_pat}[^\"]*\"" "$msgfile" 2>/dev/null; then
              hit=true
              break
            fi
          done
          $hit && break
        done
        $hit && break
      done
      $hit && break
    done
    $hit && found+=("$(basename "$root")")
  done
  echo "${found[*]:-}"
}

print_header() {
  # ── Header ──────────────────────────────────────────────────────────────────
  if [[ "$MODE" != "json" ]]; then
    printf "%smacOS Posture Audit%s\n" "$BOLD" "$NC"
    printf "%sRead-only. No changes will be made.%s\n" "$DIM" "$NC"
    printf "%sHost: %s · macOS %s · arch %s%s\n" "$DIM" "$(redact host "$(hostname)")" "$MACOS_VER" "$ARCH" "$NC"
    $QUICK && printf "%sQuick mode: skipping sudo-required checks%s\n" "$DIM" "$NC"
    ! $NETWORK && printf "%sOffline mode: external network probes disabled (use --network to enable)%s\n" "$DIM" "$NC"
    $REDACT && printf "%sRedaction mode: hostname / email / usernames / IPs / paths masked%s\n" "$DIM" "$NC"
    [[ "${PROFILE:-normal}" != "normal" ]] && printf "%sProfile: %s (severity calibration applied)%s\n" "$DIM" "$PROFILE" "$NC"
  fi

}

# Section functions intentionally keep existing assignment semantics.
# Bash variables are global by default; avoiding broad local rewrites keeps this refactor mechanical.

section_01_system_integrity() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 01 · System Integrity (Disk & Boot)
  # ═════════════════════════════════════════════════════════════════════════════
  section "01 · System Integrity (Disk & Boot)"

  if csrutil status 2>/dev/null | grep -qi "enabled"; then
    pass "SIP (System Integrity Protection) is enabled" "system.sip.enabled"
  else
    fail "SIP is disabled" "Re-enable from Recovery Mode: csrutil enable" "system.sip.enabled"
  fi

  if spctl --status 2>/dev/null | grep -qi "assessments enabled"; then
    pass "Gatekeeper is enabled" "system.gatekeeper.enabled"
  else
    fail "Gatekeeper is disabled" "Run: sudo spctl --master-enable" "system.gatekeeper.enabled"
  fi

  FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
  if echo "$FV_STATUS" | grep -q "FileVault is On"; then
    pass "FileVault is on (full-disk encryption active)" "system.filevault.on"
  elif echo "$FV_STATUS" | grep -q "Off"; then
    fail "FileVault is OFF" "Enable: System Settings → Privacy & Security → FileVault → Turn On" "system.filevault.on"
  else
    warn "FileVault state unknown" "Run manually: fdesetup status" "system.filevault.on"
  fi

  if $IS_APPLE_SILICON; then
    if $QUICK; then
      skip "bputil boot security check (requires sudo)" "" "boot.secure.full"
    else
      BPUTIL=$(sudo -n bputil -d 2>/dev/null || true)
      if [[ -n "$BPUTIL" ]]; then
        if echo "$BPUTIL" | grep -q "Security Mode:[[:space:]]*Full"; then
          pass "Apple Silicon Secure Boot: Full Security" "boot.secure.full"
        else
          fail "Apple Silicon Secure Boot is not Full" "Boot to Recovery → Startup Security Utility → Full Security" "boot.secure.full"
        fi
        if echo "$BPUTIL" | grep -q "3rd Party Kexts Status:[[:space:]]*Disabled"; then
          pass "Third-party kernel extensions disabled" "boot.kexts.disabled"
        else
          warn "Third-party kexts allowed" "Disable unless you actively need them" "boot.kexts.disabled"
        fi
      else
        skip "bputil requires sudo" "Run manually: sudo bputil -d | grep 'Security Mode'" "boot.secure.full"
      fi
    fi
  else
    skip "Apple Silicon boot security checks (Intel Mac)" "" "boot.secure.full"
  fi

}

section_02_login_lock() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 02 · Login & Lock Screen
  # ═════════════════════════════════════════════════════════════════════════════
  section "02 · Login & Lock Screen"

  AUTO_LOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "")
  if [[ -z "$AUTO_LOGIN" ]]; then
    pass "Auto-login is disabled" "login.autologin.disabled"
  else
    fail "Auto-login is enabled (user: $(redact user "$AUTO_LOGIN"))" "Disable: System Settings → Users & Groups → Automatic login → Off" "login.autologin.disabled"
  fi

  # Screen lock — sysadminctl on modern macOS, fall back to defaults read on older.
  SCREEN_LOCK_STATUS=""
  if command -v sysadminctl >/dev/null 2>&1; then
    SCREEN_LOCK_STATUS=$(sysadminctl -screenLock status 2>&1 || true)
  fi
  if echo "$SCREEN_LOCK_STATUS" | grep -qi "immediate"; then
    pass "Screen lock requires password immediately (sysadminctl)" "login.lock.immediate"
  elif echo "$SCREEN_LOCK_STATUS" | grep -qi "is off"; then
    fail "Screen does not lock automatically" "System Settings → Lock Screen → Require password after screensaver: Immediately" "login.lock.immediate"
  elif echo "$SCREEN_LOCK_STATUS" | grep -qiE "[0-9]+[[:space:]]*second"; then
    DELAY_VAL=$(echo "$SCREEN_LOCK_STATUS" | grep -oE '[0-9]+[[:space:]]*second[s]?' | head -1)
    warn "Screen lock has a delay (${DELAY_VAL})" "Set to 'Immediately' in Lock Screen settings" "login.lock.immediate"
  else
    ASK_PW=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "")
    ASK_PW_DELAY=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "")
    if [[ "$ASK_PW" == "1" ]] && [[ "$ASK_PW_DELAY" == "0" ]]; then
      pass "Screen lock requires password immediately" "login.lock.immediate"
    elif [[ "$ASK_PW" == "1" ]]; then
      warn "Screen lock asks for password but with ${ASK_PW_DELAY}s delay" "Set to 'Immediately' in Lock Screen settings" "login.lock.immediate"
    else
      skip "Screen lock state not readable via legacy keys" "Verify manually: System Settings → Lock Screen" "login.lock.immediate"
    fi
  fi

  LOGIN_WINDOW_TYPE=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo "0")
  if [[ "$LOGIN_WINDOW_TYPE" == "1" ]]; then
    pass "Login window: Name and password (no user list shown)" "login.window.namepw"
  else
    warn "Login window shows user list" "Better: Lock Screen → Login window shows → Name and password" "login.window.namepw"
  fi

  # Touch ID for sudo
  if [[ -f /etc/pam.d/sudo_local ]] && grep -Eq "^auth[[:space:]]+sufficient[[:space:]]+pam_tid\.so" /etc/pam.d/sudo_local 2>/dev/null; then
    pass "Touch ID for sudo is enabled (via /etc/pam.d/sudo_local)" "login.touchid.sudo"
  elif grep -Eq "^auth[[:space:]]+sufficient[[:space:]]+pam_tid\.so" /etc/pam.d/sudo 2>/dev/null; then
    warn "Touch ID for sudo enabled in /etc/pam.d/sudo (gets overwritten on macOS updates)" "Move to /etc/pam.d/sudo_local (template at /etc/pam.d/sudo_local.template)" "login.touchid.sudo"
  else
    warn "Touch ID for sudo not enabled" "sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local && sudo nano /etc/pam.d/sudo_local" "login.touchid.sudo"
  fi

  # Composite: physical-theft resistance.
  # FileVault encrypts the disk at rest, but a thief grabbing an unlocked
  # or sleeping Mac can extract the key from memory. Need three things
  # together: FV on, screen locks immediately, login window doesn't
  # advertise account names. If FV is off the check is moot — the
  # FileVault failure itself is the bigger story.
  fv=$(_status_of "system.filevault.on")
  lock=$(_status_of "login.lock.immediate")
  win=$(_status_of "login.window.namepw")
  if [[ "$fv" != "pass" ]]; then
    skip "Physical-theft resistance: FileVault not on — fix that first" "$fv == pass is the prerequisite for this composite to mean anything." "system.theft_resistance"
  elif [[ "$lock" == "pass" && "$win" == "pass" ]]; then
    pass "Physical-theft resistance: FileVault on + lock immediate + login window hides users" "system.theft_resistance"
  else
    weak=""
    [[ "$lock" != "pass" ]] && weak="${weak}lock-not-immediate "
    [[ "$win" != "pass" ]] && weak="${weak}user-list-shown "
    warn "Physical-theft resistance: FileVault on but lock posture loose (${weak% })" "FV protects a powered-off disk; a sleeping/unlocked Mac still leaks the key from memory. Tighten: lock immediately + hide user list." "system.theft_resistance"
  fi

}

section_03_privacy_telemetry() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 03 · Privacy, Telemetry & Lockdown Mode
  # ═════════════════════════════════════════════════════════════════════════════
  section "03 · Privacy, Telemetry & Lockdown Mode"

  # Lockdown Mode — Apple's anti-mercenary-spyware mode. It disables WebKit JIT,
  # breaks many attachment types, kills FaceTime from non-contacts, blocks config
  # profiles, etc. Designed for journalists / activists / actively-targeted users.
  # Off is normal for most users; only on if you have a specific reason.
  LDM=$(defaults read NSGlobalDomain LDMGlobalEnabled 2>/dev/null || echo "0")
  if [[ "$LDM" == "1" ]]; then
    pass "Lockdown Mode is enabled (max protection — significant web/app friction expected)" "privacy.lockdown.on"
  else
    skip "Lockdown Mode is off (Apple-recommended default for non-targeted users)" "Only turn on if you're a likely target of nation-state spyware (journalist, activist, dissident, public-figure dev). For typical web3 dev work, leaving it off is correct." "privacy.lockdown.on"
  fi

  # Apple personalized ads — modern macOS default is OFF; the keys only get written
  # when the user explicitly toggles. Treat "no key" as "default secure" rather than skip.
  ADS_MODERN=$(defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>/dev/null || echo "")
  ADS_LEGACY=$(defaults read /Library/Preferences/com.apple.AdLib forceLimitAdTracking 2>/dev/null || echo "")
  if [[ "$ADS_MODERN" == "0" ]] || [[ "$ADS_LEGACY" == "1" ]]; then
    pass "Apple personalized ads are off (explicit setting)" "privacy.ads.off"
  elif [[ "$ADS_MODERN" == "1" ]] || [[ "$ADS_LEGACY" == "0" ]]; then
    warn "Apple personalized ads are on" "System Settings → Privacy & Security → Apple Advertising → toggle off" "privacy.ads.off"
  else
    # No explicit override — modern macOS default is off (since Catalina). Pass with a hint.
    pass "Apple personalized ads: no override (macOS default is off on modern versions)" "privacy.ads.off"
  fi

  # Analytics & Improvements sharing
  SUBMIT_DIAG=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null || echo "?")
  if [[ "$SUBMIT_DIAG" == "0" ]]; then
    pass "Analytics & Improvements sharing is off" "privacy.diagnostics.off"
  elif [[ "$SUBMIT_DIAG" == "1" ]]; then
    warn "Analytics sharing is on" "System Settings → Privacy & Security → Analytics & Improvements → off" "privacy.diagnostics.off"
  else
    skip "Analytics sharing state unreadable" "" "privacy.diagnostics.off"
  fi

}

section_04_firewall_sharing() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 04 · Network — Firewall & Sharing
  # ═════════════════════════════════════════════════════════════════════════════
  section "04 · Network — Firewall & Sharing"

  FW_TOOL="/usr/libexec/ApplicationFirewall/socketfilterfw"
  if [[ -x "$FW_TOOL" ]]; then
    FW_STATE_TXT=$("$FW_TOOL" --getglobalstate 2>/dev/null || echo "")
    if echo "$FW_STATE_TXT" | grep -qi "Block all DNS\|specifically allowed"; then
      pass "App Firewall: block all incoming connections (max posture)" "network.firewall.on"
    elif echo "$FW_STATE_TXT" | grep -qi "enabled"; then
      pass "App Firewall: enabled" "network.firewall.on"
      if ! echo "$FW_STATE_TXT" | grep -qi "block all"; then
        warn "App Firewall not in block-all mode" "Max posture: 'Block all incoming connections' in firewall options" "network.firewall.blockall"
      fi
    elif echo "$FW_STATE_TXT" | grep -qi "disabled"; then
      fail "Application Firewall is OFF" "Enable: System Settings → Network → Firewall → Turn On" "network.firewall.on"
    else
      skip "App Firewall state could not be parsed" "Run manually: $FW_TOOL --getglobalstate" "network.firewall.on"
    fi

    STEALTH_TXT=$("$FW_TOOL" --getstealthmode 2>/dev/null || echo "")
    # macOS 13/14 said "stealth mode enabled|disabled"; macOS 15+ shifted to
    # "Firewall stealth mode is on|off". Match both phrasings.
    if echo "$STEALTH_TXT" | grep -qiE "stealth mode (enabled|is on)"; then
      pass "Firewall stealth mode is on" "network.firewall.stealth"
    elif echo "$STEALTH_TXT" | grep -qiE "stealth mode (disabled|is off)"; then
      warn "Firewall stealth mode is off" "Firewall Options → Enable stealth mode" "network.firewall.stealth"
    else
      skip "Stealth mode state could not be parsed" "Run: $FW_TOOL --getstealthmode" "network.firewall.stealth"
    fi
  else
    skip "Application Firewall CLI not found" "Path missing: $FW_TOOL" "network.firewall.on"
  fi

  # Remote Login (SSH server)
  if $QUICK; then
    skip "Remote Login state (requires sudo)" "" "network.remotelogin.off"
  else
    REMOTE_LOGIN=$(sudo -n systemsetup -getremotelogin 2>/dev/null | tail -1 || echo "")
    if echo "$REMOTE_LOGIN" | grep -qi "off"; then
      pass "Remote Login (SSH) is off" "network.remotelogin.off"
    elif echo "$REMOTE_LOGIN" | grep -qi "on"; then
      warn "Remote Login (SSH) is on" "Disable unless needed: System Settings → General → Sharing → Remote Login" "network.remotelogin.off"
    else
      skip "Remote Login state requires sudo" "" "network.remotelogin.off"
    fi
  fi

  # Common sharing services via launchctl
  SHARING_FOUND=0
  for svc in com.apple.screensharing com.apple.smbd com.apple.AirPlayXPCHelper com.apple.RemoteDesktop.PrivilegeProxy; do
    if launchctl list 2>/dev/null | grep -q "$svc"; then
      case "$svc" in
      com.apple.screensharing) warn "Screen Sharing service is loaded" "Disable: Sharing → Screen Sharing" "network.sharing.screensharing" ;;
      com.apple.smbd) warn "File Sharing (SMB) is loaded" "Disable: Sharing → File Sharing" "network.sharing.smbd" ;;
      esac
      SHARING_FOUND=$((SHARING_FOUND + 1))
    fi
  done
  [[ "$SHARING_FOUND" -eq 0 ]] && pass "No common sharing services running (Screen Sharing, File Sharing)" "network.sharing.none"

  # Internet Sharing
  if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -q "Enabled = 1"; then
    fail "Internet Sharing is on" "Disable: System Settings → Sharing → Internet Sharing" "network.intsharing.off"
  else
    pass "Internet Sharing is off" "network.intsharing.off"
  fi

  _check_listening_all_interfaces
}

_check_listening_all_interfaces() {
  # network.listening.all_interfaces — flag TCP listeners bound to 0.0.0.0
  # or the IPv4/IPv6 wildcard address. Localhost-only listeners
  # (127.0.0.1, [::1]) are fine; interface-specific binds (192.168.x.x)
  # are assumed intentional and skipped.
  #
  # Real-world failure mode: a developer runs `vite --host 0.0.0.0`,
  # `python -m http.server`, or `next dev -H 0.0.0.0` for cross-device
  # testing and forgets to stop it. Anything on the local network can
  # reach the service. On a co-working space or coffee shop wifi that's
  # the entire room.
  #
  # We parse `lsof -nP -iTCP -sTCP:LISTEN -F pcn`, which emits one line
  # per field with a single-letter prefix: p<pid>, c<command>, n<name>.
  # The accumulator pairs each n with the most recent p+c.
  local LSOF_OUT rc=0
  LSOF_OUT=$(lsof -nP -iTCP -sTCP:LISTEN -F pcn 2>/dev/null) || rc=$?
  if [[ "$rc" -ne 0 && -z "$LSOF_OUT" ]]; then
    skip "lsof unavailable; cannot check listening ports" "" "network.listening.all_interfaces"
    return
  fi
  local hits=() line cmd="" pid="" name port
  while IFS= read -r line; do
    case "$line" in
    p*) pid="${line#p}" ;;
    c*) cmd="${line#c}" ;;
    n*)
      name="${line#n}"
      case "$name" in
      \*:* | 0.0.0.0:* | \[::\]:*)
        port="${name##*:}"
        hits+=("${cmd}:${port}")
        ;;
      esac
      ;;
    esac
  done <<<"$LSOF_OUT"
  : "$pid" # silence shellcheck about unused
  if [[ ${#hits[@]} -eq 0 ]]; then
    pass "No TCP listeners on all-interfaces (0.0.0.0 / *)" "network.listening.all_interfaces"
    return
  fi
  if [[ "$REDACT" == "true" ]]; then
    # Strip process names; keep ports only so a sysadmin reading a
    # redacted report can still spot e.g. ":3000 :8080" and know
    # something is listening on dev-server ports.
    local ports=() h
    for h in "${hits[@]}"; do
      ports+=(":${h##*:}")
    done
    warn "${#hits[@]} TCP listener(s) on all-interfaces: ${ports[*]}" "Each is reachable from the local network. Localhost-bind (127.0.0.1) is preferred for dev servers. Stop them when not in use, or bind to a specific interface." "network.listening.all_interfaces"
  else
    warn "TCP listeners on all-interfaces: ${hits[*]}" "Each is reachable from the local network. Localhost-bind (127.0.0.1) is preferred — most dev servers (vite, next, python -m http.server) support --host 127.0.0.1 / --bind 127.0.0.1. Stop them when not in use, or bind to a specific interface." "network.listening.all_interfaces"
  fi
}

section_05_airdrop_bluetooth() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 05 · Network — AirDrop & Bluetooth
  # ═════════════════════════════════════════════════════════════════════════════
  section "05 · Network — AirDrop & Bluetooth"

  # AirDrop discoverability — try multiple keys and the plist file directly.
  # "No One" in System Settings doesn't always write to defaults; check the plist file too.
  AIRDROP=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null || echo "")
  AIRDROP_DISABLED=$(defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null || echo "")
  SHARINGD_PLIST="$HOME/Library/Preferences/com.apple.sharingd.plist"
  SHARINGD_DUMP=""
  [[ -f "$SHARINGD_PLIST" ]] && SHARINGD_DUMP=$(plutil -p "$SHARINGD_PLIST" 2>/dev/null || echo "")

  # Pull DiscoverableMode from plist dump if not already in `defaults` output
  if [[ -z "$AIRDROP" ]] && [[ -n "$SHARINGD_DUMP" ]]; then
    AIRDROP=$(echo "$SHARINGD_DUMP" | awk -F'"' '/DiscoverableMode/ {print $4; exit}')
  fi

  if [[ "$AIRDROP_DISABLED" == "1" ]]; then
    pass "AirDrop is fully disabled (com.apple.NetworkBrowser DisableAirDrop=1)" "network.airdrop.discoverable"
  else
    case "$AIRDROP" in
    "Off" | "No One") pass "AirDrop receive: Off / No One" "network.airdrop.discoverable" ;;
    "Contacts Only") pass "AirDrop receive: Contacts Only" "network.airdrop.discoverable" ;;
    "Everyone" | "Everybody") warn "AirDrop receive: Everyone" "Set to 'Off' or 'Contacts Only' (Control Center → AirDrop)" "network.airdrop.discoverable" ;;
    "Everybody for 10 minutes") warn "AirDrop receive: Everybody (10 min auto-revert)" "" "network.airdrop.discoverable" ;;
    "")
      # Setting never explicitly written. Modern macOS default is "Contacts Only" — treat as PASS, not skip.
      pass "AirDrop discoverability not in defaults (macOS default 'Contacts Only' or 'No One')" "network.airdrop.discoverable"
      ;;
    *) skip "AirDrop discoverability: $AIRDROP" "" "network.airdrop.discoverable" ;;
    esac
  fi

  BT_STATE=$(system_profiler SPBluetoothDataType 2>/dev/null | awk -F': ' '/State:/ {print $2; exit}' | tr -d '\r')
  case "$BT_STATE" in
  "Off") pass "Bluetooth is off" "network.bluetooth.off" ;;
  "On") warn "Bluetooth is on" "Disable when not in use; never use BT keyboard for seed phrase entry" "network.bluetooth.off" ;;
  *) skip "Bluetooth state could not be parsed" "" "network.bluetooth.off" ;;
  esac

  _check_wifi_known_networks
}

_check_wifi_known_networks() {
  # network.wifi.known_networks — count remembered SSIDs. macOS remembers
  # every Wi-Fi network the device has joined and probes them when
  # scanning, which is a triangulation surface (a passive attacker can
  # correlate the SSID list to known coffee shops, conference networks,
  # the user's home / office). On Big Sur and later the list lives in
  # /Library/Preferences/com.apple.wifi.known-networks.plist; older
  # macOS used .../SystemConfiguration/com.apple.airport.preferences.
  # The file is owned by root and not always world-readable, so we may
  # need sudo. We try unprivileged first to avoid asking when not
  # necessary.
  #
  # WIFI_KNOWN_PLISTS is overridable so the test suite can point at a
  # fixture.
  if [[ -z "${WIFI_KNOWN_PLISTS+set}" ]]; then
    WIFI_KNOWN_PLISTS=(
      "/Library/Preferences/com.apple.wifi.known-networks.plist"
      "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
    )
  fi
  local plist found_plist="" dump=""
  for plist in "${WIFI_KNOWN_PLISTS[@]}"; do
    if [[ -f "$plist" ]]; then
      found_plist="$plist"
      # Try unprivileged read first.
      dump=$(plutil -p "$plist" 2>/dev/null || echo "")
      if [[ -z "$dump" ]] && ! $QUICK; then
        # Permission denied — try sudo -n (non-interactive). If sudo also
        # fails, fall through to the skip-with-advisory.
        dump=$(sudo -n plutil -p "$plist" 2>/dev/null || echo "")
      fi
      break
    fi
  done
  if [[ -z "$found_plist" ]]; then
    skip "Wi-Fi known networks plist not found" "" "network.wifi.known_networks"
    return
  fi
  if [[ -z "$dump" ]]; then
    skip "Wi-Fi known networks plist not readable (try with sudo)" "Rerun with sudo to enumerate. The list is at $found_plist and grows with every joined network." "network.wifi.known_networks"
    return
  fi
  # SSIDs appear as either modern top-level keys (Big Sur+) or older
  # nested SSIDString / SSID_STR fields. Some plists contain BOTH (modern
  # format with a legacy compatibility section), so a single grep across
  # all patterns would double-count. Probe modern format first; only
  # fall back to legacy if zero modern matches.
  #
  # grep -c exits 1 when there are zero matches but still prints "0", so
  # any `|| echo 0` fallback produces a two-line result that breaks the
  # subsequent [[ -eq 0 ]] comparison. Swallow the exit with `|| true`.
  local ssid_count modern_count legacy_count
  modern_count=$(printf '%s' "$dump" | grep -cE '"wifi.network.ssid.[^"]+"|"network_ssid" =>' 2>/dev/null || true)
  modern_count=${modern_count:-0}
  if [[ "$modern_count" -gt 0 ]]; then
    ssid_count="$modern_count"
  else
    legacy_count=$(printf '%s' "$dump" | grep -cE '"SSIDString" =>|"SSID_STR" =>' 2>/dev/null || true)
    legacy_count=${legacy_count:-0}
    ssid_count="$legacy_count"
  fi
  if [[ "$ssid_count" -eq 0 ]]; then
    skip "Wi-Fi known networks: count not parsable from this plist format" "Plist found but SSID extraction yielded zero matches. Format may have changed; consider opening an issue with 'plutil -p $found_plist | head' (redact sensitive SSIDs)." "network.wifi.known_networks"
  elif [[ "$ssid_count" -le 30 ]]; then
    pass "Wi-Fi known networks: $ssid_count (within reasonable history)" "network.wifi.known_networks"
  else
    warn "Wi-Fi known networks: $ssid_count remembered — consider pruning" "Each remembered SSID is probed when scanning, which can be used to triangulate where you've been. Prune via System Settings → Wi-Fi → 'Advanced…' → remove networks you no longer trust or use." "network.wifi.known_networks"
  fi
}

_check_vpn_killswitch() {
  # network.vpn.killswitch — verify (where the brand exposes a settings
  # file) that the killswitch / always-on / "block when disconnected"
  # mode is enabled. Without it, brief VPN drops leak your real IP to
  # whatever you were connecting to — the exact failure mode the user
  # buys a VPN to avoid.
  #
  # Per-brand support is currently:
  #   - Mullvad: settings.json under ~/Library/Application Support/
  #     Mullvad VPN/. The `block_when_disconnected` key is grep-able and
  #     reliable. Pass if true, warn if false.
  #   - ProtonVPN, NordVPN, Windscribe, etc: settings live in binary
  #     plists or sqlite DBs that aren't safe to parse read-only without
  #     more work. We fall back to a skip-with-advisory pointing to the
  #     in-app toggle.
  #
  # Skip entirely if no known VPN brand is installed.
  # VPN_KILLSWITCH_ROOTS is overridable for tests.
  if [[ -z "${VPN_KILLSWITCH_ROOTS+set}" ]]; then
    VPN_KILLSWITCH_ROOTS=("$HOME")
  fi
  local VPN_KS_REPORT=()
  local ks_root mv_settings
  for ks_root in "${VPN_KILLSWITCH_ROOTS[@]}"; do
    mv_settings="$ks_root/Library/Application Support/Mullvad VPN/settings.json"
    if [[ -f "$mv_settings" ]]; then
      if grep -qE '"block_when_disconnected"[[:space:]]*:[[:space:]]*true' "$mv_settings" 2>/dev/null; then
        VPN_KS_REPORT+=("mullvad:on")
      elif grep -qE '"block_when_disconnected"[[:space:]]*:[[:space:]]*false' "$mv_settings" 2>/dev/null; then
        VPN_KS_REPORT+=("mullvad:off")
      else
        VPN_KS_REPORT+=("mullvad:unknown")
      fi
      break
    fi
  done
  for ks_root in "${VPN_KILLSWITCH_ROOTS[@]}"; do
    if [[ -d "$ks_root/Library/Application Support/ProtonVPN" ]] || [[ -d "$ks_root/Library/Application Support/Proton/Proton VPN" ]]; then
      VPN_KS_REPORT+=("protonvpn:advisory")
      break
    fi
  done
  for ks_root in "${VPN_KILLSWITCH_ROOTS[@]}"; do
    if [[ -d "$ks_root/Library/Application Support/nordvpn-app" ]] || [[ -d "$ks_root/Library/Application Support/NordVPN" ]]; then
      VPN_KS_REPORT+=("nordvpn:advisory")
      break
    fi
  done
  if [[ ${#VPN_KS_REPORT[@]} -eq 0 ]]; then
    skip "No supported VPN brand for killswitch verification" "" "network.vpn.killswitch"
    return
  fi
  local ks_fail=false ks_advisory=false entry
  for entry in "${VPN_KS_REPORT[@]}"; do
    case "$entry" in
    *:off) ks_fail=true ;;
    *:advisory | *:unknown) ks_advisory=true ;;
    esac
  done
  if [[ "$ks_fail" == "true" ]]; then
    warn "VPN killswitch is OFF on at least one installed VPN — drops leak your real IP" "Mullvad: toggle 'Always require VPN' in Preferences → VPN settings (or 'mullvad always-require-vpn set on'). Without this, every VPN reconnect briefly bypasses the tunnel." "network.vpn.killswitch"
  elif [[ "$ks_advisory" == "true" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      skip "VPN(s) detected; verify killswitch / always-on manually" "Killswitch state is not readable from the CLI for some brands. ProtonVPN: Preferences → Connection → Kill Switch. NordVPN: Preferences → Kill Switch." "network.vpn.killswitch"
    else
      skip "VPN(s) detected; verify killswitch manually: ${VPN_KS_REPORT[*]}" "Killswitch state is not readable from the CLI for some brands. ProtonVPN: Preferences → Connection → Kill Switch. NordVPN: Preferences → Kill Switch." "network.vpn.killswitch"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      pass "VPN killswitch is ON (verified for ${#VPN_KS_REPORT[@]} brand)" "network.vpn.killswitch"
    else
      pass "VPN killswitch is ON (verified: ${VPN_KS_REPORT[*]})" "network.vpn.killswitch"
    fi
  fi
}

section_06_dns_outbound() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 06 · Network — DNS & Outbound
  # ═════════════════════════════════════════════════════════════════════════════
  section "06 · Network — DNS & Outbound"

  # NextDNS — profile installation is the primary signal; live test is supplementary.
  NEXTDNS_PROFILE=false
  if profiles -L 2>/dev/null | grep -qi "nextdns"; then
    NEXTDNS_PROFILE=true
  elif profiles list 2>/dev/null | grep -qi "nextdns"; then
    NEXTDNS_PROFILE=true
  elif system_profiler SPConfigurationProfileDataType 2>/dev/null | grep -qi "nextdns"; then
    NEXTDNS_PROFILE=true
  fi

  # Live test only runs in --network mode; default is offline (no external calls).
  NEXTDNS_TEST=""
  NEXTDNS_OK=false
  NEXTDNS_DOH=false
  if $NETWORK; then
    NEXTDNS_TEST=$(curl -s --max-time 5 https://test.nextdns.io 2>/dev/null || echo "")
    if echo "$NEXTDNS_TEST" | grep -q '"status":"ok"'; then
      NEXTDNS_OK=true
      echo "$NEXTDNS_TEST" | grep -q '"protocol":"DOH"' && NEXTDNS_DOH=true
    fi
  fi

  if $NEXTDNS_PROFILE && $NEXTDNS_OK; then
    if $NEXTDNS_DOH; then
      pass "NextDNS profile installed and live-routing confirmed via DoH" "network.dns.nextdns"
    else
      pass "NextDNS profile installed and live-routing confirmed" "network.dns.nextdns"
    fi
  elif $NEXTDNS_PROFILE; then
    if $NETWORK; then
      pass "NextDNS profile installed (verify live routing at my.nextdns.io → Logs)" "network.dns.nextdns"
    else
      pass "NextDNS profile installed (offline mode — pass --network to verify live routing)" "network.dns.nextdns"
    fi
  elif $NEXTDNS_OK; then
    pass "NextDNS active via live test (no profile detected — may be configured differently)" "network.dns.nextdns"
  elif [[ -n "$NEXTDNS_TEST" ]] && echo "$NEXTDNS_TEST" | grep -q '"status":"unconfigured"'; then
    warn "NextDNS reachable but profile not installed" "Install your config profile from my.nextdns.io → Setup → Apple" "network.dns.nextdns"
  else
    skip "No NextDNS detected" "Optional: nextdns.io → install macOS profile (DoH, blocklists)" "network.dns.nextdns"
  fi

  # Active resolvers (informational)
  # Preserve scutil's primary-first order with awk dedup, then take the top
  # three. The previous `sort -u | head -3` re-ordered lexically — for
  # 1.1.1.1 / 8.8.8.8 / 192.168.1.1 the local router got pulled forward
  # and looked like the primary. Under --redact the IP list is replaced by
  # a count to avoid emitting `<IP>,<IP>,<IP>` which is both unhelpful and
  # still implies how many resolvers the host has.
  RESOLVERS=$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/ {print $3}' | awk '!seen[$0]++' | head -3 | paste -sd, -)
  if [[ -n "$RESOLVERS" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      RES_COUNT=$( (printf '%s' "$RESOLVERS" | tr ',' '\n' | grep -c '.') || true)
      RES_COUNT=${RES_COUNT:-0}
      skip "${RES_COUNT} active resolver(s) configured" "" "network.dns.resolvers"
    else
      skip "Active resolver(s): $RESOLVERS" "" "network.dns.resolvers"
    fi
  fi

  # DoH/DoT configuration profiles (count, informational).
  DOH_PROFILES=$( (profiles list 2>/dev/null | grep -ci "dnsSettings\|nextdns\|cloudflare-dns\|adguard\|controld") || true)
  DOH_PROFILES=${DOH_PROFILES:-0}

  # VPN client — checked here so the encrypted-DNS posture can factor it in.
  VPN_PROCS=""
  for proc in ProtonVPN Mullvad WireGuard tunnelblickd OpenVPN Tailscale openvpn; do
    if pgrep -qi "$proc" 2>/dev/null; then VPN_PROCS+="$proc "; fi
  done

  # Encrypted-DNS posture. Three signals worth distinguishing:
  #  1. scutil --dns currently advertises a DoH/DoT resolver -> encrypted, active right now.
  #  2. A DoH/DoT macOS profile is installed (or NextDNS profile from earlier) -> configured, may need a network refresh to activate.
  #  3. A VPN is running -> the VPN may be tunneling DNS, but we cannot tell from the snapshot.
  # If none of those hold, traffic is going to the ISP in plaintext — warn.
  ENCRYPTED_RESOLVER=$( (scutil --dns 2>/dev/null | grep -ciE "DNS over (HTTPS|TLS)") || true)
  ENCRYPTED_RESOLVER=${ENCRYPTED_RESOLVER:-0}
  if [[ "$ENCRYPTED_RESOLVER" -gt 0 ]]; then
    pass "Encrypted DNS active (DoH / DoT advertised by scutil)" "network.dns.encrypted"
  elif $NEXTDNS_PROFILE || [[ "$DOH_PROFILES" -gt 0 ]]; then
    pass "Encrypted DNS profile installed (NextDNS / DoH / DoT) — may need a network refresh to activate" "network.dns.encrypted"
  elif [[ -n "$VPN_PROCS" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      _record skip "Plaintext DNS resolvers, but a VPN client is running — most VPNs tunnel DNS" "When VPN is OFF, DNS goes to your ISP in plaintext. Install an encrypted-DNS macOS profile (NextDNS / AdGuard / Cloudflare 1.1.1.1 / ControlD) for always-on coverage." "network.dns.encrypted"
    else
      _record skip "Plaintext DNS resolvers, but VPN is running ($VPN_PROCS) — most VPNs tunnel DNS" "When VPN is OFF, DNS goes to your ISP in plaintext. Install an encrypted-DNS macOS profile (NextDNS / AdGuard / Cloudflare 1.1.1.1 / ControlD) for always-on coverage." "network.dns.encrypted"
    fi
  else
    warn "Plaintext DNS — every query is visible to your ISP / network operator" "Install an encrypted-DNS macOS profile (NextDNS / AdGuard / Cloudflare 1.1.1.1 / ControlD) or use a VPN that tunnels DNS." "network.dns.encrypted"
  fi
  if [[ -n "$VPN_PROCS" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "VPN client running" "network.vpn.running"
    else
      pass "VPN client running: ${VPN_PROCS}" "network.vpn.running"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "No VPN client process detected" "Use a reputable VPN when traveling or using untrusted networks." "network.vpn.running"
    else
      skip "No VPN client process detected" "ProtonVPN / Mullvad / WireGuard recommended for travel" "network.vpn.running"
    fi
  fi

  _check_vpn_killswitch

  # Outbound monitor
  if pgrep -qi littlesnitch 2>/dev/null || pgrep -qi com.objective-see.lulu 2>/dev/null; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Outbound monitor running" "network.outboundmonitor.running"
    else
      pass "Outbound monitor running (Little Snitch or LuLu)" "network.outboundmonitor.running"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      warn "No outbound network monitor detected" "Install a reputable outbound firewall to catch unexpected network egress." "network.outboundmonitor.running"
    else
      warn "No outbound network monitor detected" "Install Little Snitch (paid) or LuLu (free) — catches malware exfil" "network.outboundmonitor.running"
    fi
  fi

}

section_07_filters_proxies() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 07 · Network — Filters & Proxies
  # ═════════════════════════════════════════════════════════════════════════════
  section "07 · Network — Filters & Proxies"

  PROXY_DUMP=$(scutil --proxy 2>/dev/null || echo "")
  if [[ -z "$PROXY_DUMP" ]]; then
    skip "Could not read proxy config (scutil --proxy returned nothing)" "" "network.proxy.types"
  else
    PROXY_ACTIVE=()
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*HTTPEnable *: *1" && PROXY_ACTIVE+=("HTTP")
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*HTTPSEnable *: *1" && PROXY_ACTIVE+=("HTTPS")
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*FTPEnable *: *1" && PROXY_ACTIVE+=("FTP")
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*SOCKSEnable *: *1" && PROXY_ACTIVE+=("SOCKS")
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*RTSPEnable *: *1" && PROXY_ACTIVE+=("RTSP")
    echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*GopherEnable *: *1" && PROXY_ACTIVE+=("Gopher")

    if [[ ${#PROXY_ACTIVE[@]} -eq 0 ]]; then
      pass "No HTTP/HTTPS/SOCKS/FTP/RTSP/Gopher proxies enabled" "network.proxy.types"
    else
      warn "Active proxy types: ${PROXY_ACTIVE[*]}" "Review: System Settings → Network → [active service] → Details → Proxies. Malware sometimes inserts proxies for traffic interception." "network.proxy.types"
    fi

    if echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*ProxyAutoConfigEnable *: *1"; then
      PAC_URL=$(echo "$PROXY_DUMP" | awk '/ProxyAutoConfigURLString *: */ {sub(/.*: */,""); print; exit}')
      if [[ "$REDACT" == "true" ]]; then
        fail "Proxy auto-config (PAC) URL is set" "Verify legitimate. PAC URLs are used by malware to redirect traffic. Disable if unfamiliar." "network.proxy.pac"
      else
        fail "Proxy auto-config (PAC) URL is set: ${PAC_URL:-unknown}" "Verify legitimate. PAC URLs are used by malware to redirect traffic. Disable if unfamiliar." "network.proxy.pac"
      fi
    else
      pass "No proxy auto-config (PAC) URL set" "network.proxy.pac"
    fi

    if echo "$PROXY_DUMP" | grep -qE "^[[:space:]]*ProxyAutoDiscoveryEnable *: *1"; then
      warn "Proxy auto-discovery (WPAD) is enabled" "Disable unless required: Network → Details → Proxies → uncheck 'Auto Proxy Discovery'" "network.proxy.wpad"
    else
      pass "Proxy auto-discovery (WPAD) is off" "network.proxy.wpad"
    fi
  fi

  # Configuration profiles (DoH, MDM, content filters).
  # `profiles -L` and `profiles list` only show user-scope without sudo; an
  # MDM-managed device would silently report "no profiles" — a false
  # negative for the corporate-management threat model. system_profiler
  # SPConfigurationProfileDataType reports device-scope without sudo.
  PROFILES_OUT=$(system_profiler SPConfigurationProfileDataType 2>/dev/null || true)
  PROFILES_OUT_USER=$(profiles -L 2>/dev/null || profiles list 2>/dev/null || true)
  [[ -n "$PROFILES_OUT_USER" ]] && PROFILES_OUT="${PROFILES_OUT}${PROFILES_OUT:+
}${PROFILES_OUT_USER}"
  if ! $QUICK; then
    PROFILES_OUT_PRIV=$(sudo -n profiles list 2>/dev/null || true)
    [[ -n "$PROFILES_OUT_PRIV" ]] && PROFILES_OUT="${PROFILES_OUT}${PROFILES_OUT:+
}${PROFILES_OUT_PRIV}"
  fi
  if [[ -n "$PROFILES_OUT" ]]; then
    # system_profiler emits one "_name" per profile; profiles list emits
    # one "attribute" per profile field — count whichever marker exists.
    # `system_profiler SPConfigurationProfileDataType` emits one
    # `Identifier:` line per profile in its text format. `profiles list`
    # emits `attribute:` rows (multiple per profile, but only when something
    # is installed). Counting Identifier lines first gives the canonical
    # device-scope count; falling back to `attribute:` lets older `profiles`
    # output still register without double-counting.
    PROFILES_COUNT=$( (echo "$PROFILES_OUT" | grep -cE '^[[:space:]]+Identifier:[[:space:]]') || true)
    PROFILES_COUNT=${PROFILES_COUNT:-0}
    if [[ "$PROFILES_COUNT" -eq 0 ]]; then
      PROFILES_COUNT=$( (echo "$PROFILES_OUT" | grep -cE '^[[:space:]]*attribute:[[:space:]]+profileIdentifier') || true)
      PROFILES_COUNT=${PROFILES_COUNT:-0}
    fi
    if [[ "$PROFILES_COUNT" -gt 0 ]]; then
      pass "$PROFILES_COUNT configuration profile(s) installed (device + user scope)" "network.profiles.installed"
      if echo "$PROFILES_OUT" | grep -qiE "filter|proxy|netex|webcontent"; then
        skip "One or more profiles look like content filters / network extensions" "Review: System Settings → Privacy & Security → Profiles. Inspect anything you didn't install yourself." "network.profiles.filters"
      fi
    else
      skip "No configuration profiles installed" "" "network.profiles.installed"
    fi
  elif $QUICK; then
    skip "Configuration profiles unreadable in --quick mode (device scope needs sudo)" "Re-run without --quick to query device-scope profiles." "network.profiles.installed"
  fi

  # System extensions (NetworkExtension framework)
  if command -v systemextensionsctl >/dev/null 2>&1; then
    SE_LIST=$(systemextensionsctl list 2>/dev/null || true)
    SE_ACTIVE=$( (echo "$SE_LIST" | grep -ic "activated enabled") || true)
    SE_ACTIVE=${SE_ACTIVE:-0}
    if [[ "$SE_ACTIVE" -gt 0 ]]; then
      if [[ "$REDACT" == "true" ]]; then
        pass "$SE_ACTIVE active system extension(s)" "network.systemextensions.active"
      else
        SE_NAMES=$(echo "$SE_LIST" | awk '/activated enabled/ { for (i=1;i<=NF;i++) if ($i ~ /\./) { print $i; break } }' | sort -u | paste -sd, -)
        pass "$SE_ACTIVE active system extension(s): ${SE_NAMES:-(names unparsed)}" "network.systemextensions.active"
      fi
      if echo "$SE_LIST" | grep -qiE "filter|netex|content"; then
        skip "Network/content-filter system extensions present" "These are normal for VPNs, AV web protection, NextDNS native client, etc. Investigate any you didn't install." "network.systemextensions.filters"
      fi
    else
      skip "No active third-party system extensions" "" "network.systemextensions.active"
    fi
  fi

  # /etc/hosts non-default entries
  HOSTS_LINES=$( (grep -cvE '^\s*(#|$|::1|127\.0\.0\.1\s+localhost|255\.|fe80::1)' /etc/hosts 2>/dev/null) || true)
  HOSTS_LINES=${HOSTS_LINES:-0}
  if [[ "$HOSTS_LINES" -eq 0 ]]; then
    pass "/etc/hosts has no non-default entries" "network.hosts.entries"
  else
    warn "/etc/hosts has $HOSTS_LINES non-default entries" "Inspect: cat /etc/hosts. Malware can plant redirects here." "network.hosts.entries"
  fi

}

# AV detection table at module scope so tests can override it before
# calling section_08_av_endpoint. Each row: BUNDLE_GLOB|PROC_ERE|DISPLAY_NAME.
# BUNDLE_GLOB may be "-" if the AV ships no app bundle. Multiple bundle
# paths can be space-separated. PROC_ERE is matched against the full
# argv via _proc_running (pgrep -fi). Either signal is enough; we
# de-dup on display name so a bundle-only or process-only hit registers
# exactly once.
AV_TABLE_DEFAULT=(
  "/Applications/Endpoint Security for Mac.app /Library/Bitdefender|BDLDaemon|Bitdefender"
  "/Applications/Malwarebytes.app|RTProtectionDaemon|malwarebytes|Malwarebytes"
  "/Applications/Sophos Endpoint.app /Library/Sophos Anti-Virus|SophosScanD|sophos|Sophos"
  "-|clamd|clamscan|ClamAV"
  "/Applications/Falcon.app|falcond|CSFalconAgent|CrowdStrike Falcon"
  "/Applications/SentinelOne.app|sentineld|SentinelAgent|SentinelOne"
  "/Applications/Avast Security.app|com.avast|Avast"
  "/Applications/Norton 360.app /Applications/Norton AntiVirus.app|symdaemon|Norton"
  "/Applications/Kaspersky Security.app|kaspersky|kav|Kaspersky"
  "/Applications/ESET Cyber Security.app /Applications/ESET Endpoint Security.app|esets_daemon|esets_proxy|ESET Cyber Security"
  "/Applications/Trend Micro Security.app|iCoreService|TrendMicro|Trend Micro"
  "/Applications/Intego VirusBarrier.app|virusbarrier|Intego VirusBarrier"
  "/Applications/Cylance.app /Applications/CylancePROTECT.app|cylance|CylanceUI|BlackBerry Cylance"
  "/Library/Application Support/Microsoft/Defender|wdavdaemon|mdatp|Microsoft Defender for Endpoint"
  "/Applications/Cisco AMP.app /opt/cisco/amp|ampdaemon|ciscod|Cisco Secure Endpoint (AMP)"
  "/Applications/CarbonBlack.app|cb-osxsensor|CbDefense|Carbon Black"
)

section_08_av_endpoint() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 08 · Antivirus & Endpoint Protection
  # ═════════════════════════════════════════════════════════════════════════════
  section "08 · Antivirus & Endpoint Protection"

  # Use the override if a test has set AV_TABLE; otherwise the default.
  if [[ -z "${AV_TABLE+x}" ]]; then
    AV_TABLE=("${AV_TABLE_DEFAULT[@]}")
  fi
  AV_FOUND=()
  for row in "${AV_TABLE[@]}"; do
    # Row schema: BUNDLES | PROC_ERE | NAME, where PROC_ERE itself may
    # contain `|` alternation (e.g. "clamd|clamscan" or "falcond|CSFalconAgent")
    # so that _proc_running can match either daemon name. The first `|` ends
    # BUNDLES; the last `|` starts NAME; everything between is the alternation
    # passed to pgrep. The previous `proc="${rest%%|*}"` only captured the
    # first alternation segment and silently dropped the rest, breaking
    # detection for engines that name their daemons differently from the
    # brand string.
    bundles="${row%%|*}"
    rest="${row#*|}"
    proc="${rest%|*}"
    name="${row##*|}"
    hit=false
    if [[ "$bundles" != "-" ]]; then
      for b in $bundles; do
        [[ -e "$b" ]] && {
          hit=true
          break
        }
      done
    fi
    if ! $hit && _proc_running "$proc"; then
      hit=true
    fi
    if $hit && ! _arr_contains "$name" ${AV_FOUND[@]+"${AV_FOUND[@]}"}; then
      AV_FOUND+=("$name")
    fi
  done

  case ${#AV_FOUND[@]} in
  0)
    if [[ "$REDACT" == "true" ]]; then
      warn "No antivirus / EDR process detected" "Consider one reputable real-time engine plus scheduled second-opinion scans." "av.engine.detected"
    else
      warn "No antivirus / EDR process detected" "Consider Bitdefender + scheduled Malwarebytes scans" "av.engine.detected"
    fi
    ;;
  1)
    if [[ "$REDACT" == "true" ]]; then
      pass "AV/EDR running (1 engine)" "av.engine.detected"
    else
      pass "AV/EDR running: ${AV_FOUND[0]}" "av.engine.detected"
    fi
    ;;
  2)
    if [[ "$REDACT" == "true" ]]; then
      pass "Two AV/EDR engines detected" "av.engine.detected"
    else
      pass "Two AV/EDR engines: ${AV_FOUND[*]}" "av.engine.detected"
    fi
    warn "Two real-time AVs may conflict" "Run one in real-time mode; demote the other to scheduled scans" "av.engine.conflict"
    ;;
  *)
    if [[ "$REDACT" == "true" ]]; then
      warn "Multiple AV/EDR engines detected (${#AV_FOUND[@]})" "Pick one for real-time, demote the rest to scheduled scans" "av.engine.detected"
    else
      warn "Multiple AV engines detected: ${AV_FOUND[*]}" "Pick one for real-time, demote the rest to scheduled scans" "av.engine.detected"
    fi
    ;;
  esac

  # Objective-See independent macOS security tools
  # Detect via /Applications/*.app (installed) — most reliable signal.
  # Augment with pgrep (running right now) so we can show status.
  OBJSEE_INSTALLED=()
  OBJSEE_RUNNING=()

  # Each entry: "AppName.app|process-pattern|Display Name"
  OBJSEE_TOOLS=(
    "LuLu.app|com.objective-see.lulu|LuLu (outbound firewall)"
    "KnockKnock.app|knockknock|KnockKnock"
    "BlockBlock Helper.app|blockblock|BlockBlock"
    "BlockBlock.app|blockblock|BlockBlock"
    "OverSight.app|oversight|OverSight (mic/cam)"
    "RansomWhere?.app|ransomwhere|RansomWhere?"
    "ReiKey.app|reikey|ReiKey (keylogger detection)"
    "Do Not Disturb.app|donotdisturb|Do Not Disturb (lid-open monitor)"
    "TaskExplorer.app|taskexplorer|TaskExplorer"
    "Netiquette.app|netiquette|Netiquette"
  )

  for entry in "${OBJSEE_TOOLS[@]}"; do
    app="${entry%%|*}"
    rest="${entry#*|}"
    proc="${rest%%|*}"
    name="${rest#*|}"
    installed=false
    running=false
    [[ -d "/Applications/$app" ]] && installed=true
    _proc_running "$proc" && running=true
    # Avoid duplicates (e.g., BlockBlock vs BlockBlock Helper)
    if $installed || $running; then
      if ! _arr_contains "$name" ${OBJSEE_INSTALLED[@]+"${OBJSEE_INSTALLED[@]}"}; then
        OBJSEE_INSTALLED+=("$name")
        $running && OBJSEE_RUNNING+=("$name")
      fi
    fi
  done

  if [[ ${#OBJSEE_INSTALLED[@]} -gt 0 ]]; then
    if [[ ${#OBJSEE_RUNNING[@]} -gt 0 ]]; then
      if [[ "$REDACT" == "true" ]]; then
        pass "Objective-See tools installed (${#OBJSEE_INSTALLED[@]})" "av.objsee.installed"
        pass "${#OBJSEE_RUNNING[@]} Objective-See tool(s) running" "av.objsee.running"
      else
        pass "Objective-See tools installed (${#OBJSEE_INSTALLED[@]}): ${OBJSEE_INSTALLED[*]}" "av.objsee.installed"
        pass "Objective-See tools running: ${OBJSEE_RUNNING[*]}" "av.objsee.running"
      fi
    else
      if [[ "$REDACT" == "true" ]]; then
        pass "Objective-See tools installed (${#OBJSEE_INSTALLED[@]})" "av.objsee.installed"
      else
        pass "Objective-See tools installed (${#OBJSEE_INSTALLED[@]}): ${OBJSEE_INSTALLED[*]}" "av.objsee.installed"
      fi
      if [[ "$REDACT" == "true" ]]; then
        warn "Installed but not running" "Open the monitoring apps to enable their protections." "av.objsee.running"
      else
        warn "Installed but not running" "Open the apps to enable monitoring (LuLu/BlockBlock/OverSight need to run to do anything)" "av.objsee.running"
      fi
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "No supplemental macOS security tools detected" "Optional: add lightweight persistence, mic/camera, or ransomware behavior monitors." "av.objsee.installed"
    else
      skip "No Objective-See tools detected" "Optional: BlockBlock + OverSight + RansomWhere? are free, lightweight, high-signal" "av.objsee.installed"
    fi
  fi

  # Browser-side AV/protection extensions — ID first, fall back to manifest name.
  TL_IN=$(detect_ext_in_chromium "jbmijkmddoamaipkkdkpklcfehfedlci")
  [[ -z "$TL_IN" ]] && TL_IN=$(detect_ext_by_name "TrafficLight|Bitdefender Web")
  if [[ -n "$TL_IN" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Browser traffic-protection extension installed" "av.browser.trafficlight"
    else
      pass "Bitdefender TrafficLight installed in: $TL_IN" "av.browser.trafficlight"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "Browser traffic-protection extension not detected" "" "av.browser.trafficlight"
    else
      skip "Bitdefender TrafficLight not installed in any Chromium browser" "" "av.browser.trafficlight"
    fi
  fi

  MBG_IN=$(detect_ext_in_chromium "ihcjicgdanjaechkgeegckofjjedodee")
  [[ -z "$MBG_IN" ]] && MBG_IN=$(detect_ext_by_name "Malwarebytes")
  if [[ -n "$MBG_IN" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Browser malware-protection extension installed" "av.browser.malwarebytes"
    else
      pass "Malwarebytes Browser Guard extension installed in: $MBG_IN" "av.browser.malwarebytes"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "Browser malware-protection extension not detected" "Distinct from standalone endpoint protection. A per-browser extension can add an extra in-page layer." "av.browser.malwarebytes"
    else
      skip "Malwarebytes Browser Guard browser-extension not detected" "Distinct from the standalone Malwarebytes app's Web Protection (which filters domains system-wide and is captured by av.engine.detected). Browser Guard is the per-browser extension that adds an extra in-page layer." "av.browser.malwarebytes"
    fi
  fi

  BDAT_IN=$(detect_ext_in_chromium "diffjaobnnkecbnaaippiljneoamenfm")
  [[ -z "$BDAT_IN" ]] && BDAT_IN=$(detect_ext_by_name "Anti.?Tracker|Bitdefender Anti")
  if [[ -n "$BDAT_IN" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Browser anti-tracker extension installed" "av.browser.antitracker"
    else
      pass "Bitdefender Anti-Tracker installed in: $BDAT_IN" "av.browser.antitracker"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "Browser anti-tracker extension not detected" "" "av.browser.antitracker"
    else
      skip "Bitdefender Anti-Tracker not detected" "" "av.browser.antitracker"
    fi
  fi

}

section_09_browsers() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 09 · Browsers
  # ═════════════════════════════════════════════════════════════════════════════
  section "09 · Browsers"

  BROWSERS_FOUND=()
  [[ -d "/Applications/Brave Browser.app" ]] && BROWSERS_FOUND+=("Brave")
  [[ -d "/Applications/Google Chrome.app" ]] && BROWSERS_FOUND+=("Chrome")
  [[ -d "/Applications/Firefox.app" ]] && BROWSERS_FOUND+=("Firefox")
  [[ -d "/Applications/Safari.app" ]] && BROWSERS_FOUND+=("Safari")
  [[ -d "/Applications/Arc.app" ]] && BROWSERS_FOUND+=("Arc")
  [[ -d "/Applications/Microsoft Edge.app" ]] && BROWSERS_FOUND+=("Edge")
  # Rubric: 1-2 browsers gives blast-radius separation (e.g. Safari for
  # general browsing, Brave/Arc for wallets / dev / sensitive logins).
  # 3 is defensible (add Firefox for compatibility testing or strict
  # tracking-protection), 4+ is almost always cruft. The threat isn't
  # "another binary on disk" — it's the per-browser extension store,
  # autofill keyring, and cookie jar that each one maintains.
  case ${#BROWSERS_FOUND[@]} in
  0) : ;;
  1 | 2)
    if [[ "$REDACT" == "true" ]]; then
      pass "${#BROWSERS_FOUND[@]} browser(s) installed — good blast-radius separation" "browser.installed"
    else
      pass "${#BROWSERS_FOUND[@]} browser(s) installed: ${BROWSERS_FOUND[*]} — good blast-radius separation" "browser.installed"
    fi
    ;;
  3)
    if [[ "$REDACT" == "true" ]]; then
      warn "3 browsers installed" "Defensible if one is for compatibility testing. Each browser is a separate extension store, autofill keyring, and cookie jar; the 4th adds attack surface without much marginal value." "browser.installed"
    else
      warn "3 browsers installed: ${BROWSERS_FOUND[*]}" "Defensible if one is for compatibility testing. Each browser is a separate extension store, autofill keyring, and cookie jar; the 4th adds attack surface without much marginal value." "browser.installed"
    fi
    ;;
  *)
    if [[ "$REDACT" == "true" ]]; then
      warn "${#BROWSERS_FOUND[@]} browsers installed" "Sweet spot is 1-2 browsers. Each extra browser is a separate extension store / autofill keyring / cookie jar. Remove the ones you no longer use." "browser.installed"
    else
      warn "${#BROWSERS_FOUND[@]} browsers installed: ${BROWSERS_FOUND[*]}" "Sweet spot is 1-2 browsers (e.g. Safari for general use + Brave/Arc for wallets and dev). Each extra browser is a separate extension store / autofill keyring / cookie jar. Remove the ones you no longer use." "browser.installed"
    fi
    ;;
  esac

  # Default browser via LaunchServices plist (binary-safe parse with plutil + awk)
  DEFAULT_BROWSER=""
  for plist in \
    "$HOME/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist" \
    "$HOME/Library/Preferences/com.apple.LaunchServices.plist"; do
    [[ -f "$plist" ]] || continue
    DEFAULT_BROWSER=$(plutil -p "$plist" 2>/dev/null | awk '
      /"LSHandlerRoleAll" => / { match($0, /"[^"]+"$/); role = substr($0, RSTART+1, RLENGTH-2); next }
      /"LSHandlerURLScheme" => "https"/ { if (role != "") { print role; exit } }
      /^[[:space:]]+[0-9]+ => \{/ { role = "" }
    ')
    [[ -n "$DEFAULT_BROWSER" ]] && break
  done

  case "$(echo "$DEFAULT_BROWSER" | tr '[:upper:]' '[:lower:]')" in
  com.apple.safari)
    if [[ "$REDACT" == "true" ]]; then
      pass "Default browser uses recommended baseline" "browser.default"
    else
      pass "Default browser: Safari (recommended baseline)" "browser.default"
    fi
    ;;
  com.brave.browser)
    if [[ "$REDACT" == "true" ]]; then
      warn "Default browser is not the recommended baseline" "Safari recommended as default — random links open with smaller blast radius" "browser.default"
    else
      warn "Default browser: Brave" "Safari recommended as default — random links open with smaller blast radius" "browser.default"
    fi
    ;;
  com.google.chrome)
    if [[ "$REDACT" == "true" ]]; then
      warn "Default browser is not the recommended baseline" "Safari recommended as default for non-work / non-wallet links" "browser.default"
    else
      warn "Default browser: Chrome" "Safari recommended as default for non-work / non-wallet links" "browser.default"
    fi
    ;;
  org.mozilla.firefox | com.microsoft.edgemac | company.thebrowser.browser)
    if [[ "$REDACT" == "true" ]]; then
      skip "Default browser: mainstream non-Safari browser" "" "browser.default"
    else
      case "$(echo "$DEFAULT_BROWSER" | tr '[:upper:]' '[:lower:]')" in
      org.mozilla.firefox) skip "Default browser: Firefox" "" "browser.default" ;;
      com.microsoft.edgemac) skip "Default browser: Edge" "" "browser.default" ;;
      company.thebrowser.browser) skip "Default browser: Arc" "" "browser.default" ;;
      esac
    fi
    ;;
  "") skip "Default browser: could not parse" "Verify: System Settings → Desktop & Dock → Default web browser" "browser.default" ;;
  *)
    if [[ "$REDACT" == "true" ]]; then
      skip "Default browser: other (non-mainstream bundle ID suppressed)" "" "browser.default"
    else
      skip "Default browser: $DEFAULT_BROWSER" "" "browser.default"
    fi
    ;;
  esac

  # browser.version_currency — bundle mtime as a proxy for "has the app
  # been updated recently". Chromium-based browsers and Firefox auto-
  # update by replacing the bundle on first launch after a release; the
  # bundle's directory mtime gets touched in the process. If mtime is
  # more than 28 days old, the user either hasn't launched the browser
  # recently or auto-update is disabled / failing. Either path means
  # exposure to CVEs that have shipped since.
  #
  # Safari is deliberately excluded — it's managed by macOS updates and
  # covered by update.auto.
  if [[ -z "${APP_ROOTS+set}" ]]; then
    APP_ROOTS=("/Applications" "$HOME/Applications")
  fi
  BROWSER_BUNDLES=(
    "Brave|Brave Browser.app"
    "Chrome|Google Chrome.app"
    "Firefox|Firefox.app"
    "Arc|Arc.app"
    "Edge|Microsoft Edge.app"
    "Opera|Opera.app"
  )
  STALE_BROWSERS=()
  FRESH_COUNT=0
  NOW=$(date +%s)
  STALE_THRESHOLD=$((28 * 86400))
  for row in "${BROWSER_BUNDLES[@]}"; do
    brand="${row%%|*}"
    bundle_name="${row##*|}"
    bundle=""
    for root in "${APP_ROOTS[@]}"; do
      if [[ -d "$root/$bundle_name" ]]; then
        bundle="$root/$bundle_name"
        break
      fi
    done
    [[ -n "$bundle" ]] || continue
    mtime=$(stat -f %m "$bundle" 2>/dev/null || echo "")
    [[ -n "$mtime" ]] || continue
    age=$((NOW - mtime))
    age_days=$((age / 86400))
    if ((age > STALE_THRESHOLD)); then
      STALE_BROWSERS+=("${brand} (${age_days}d)")
    else
      FRESH_COUNT=$((FRESH_COUNT + 1))
    fi
  done
  if [[ ${#STALE_BROWSERS[@]} -eq 0 ]]; then
    if ((FRESH_COUNT == 0)); then
      skip "No non-Safari browser installed — version currency check N/A" "" "browser.version_currency"
    else
      pass "All installed non-Safari browsers updated within 28 days (${FRESH_COUNT} checked)" "browser.version_currency"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      warn "${#STALE_BROWSERS[@]} browser(s) >28d stale" "Launch each to trigger the built-in auto-updater, or 'brew upgrade --cask <name>' if installed that way. Stale Chromium / Firefox = unpatched CVEs on every page render. Bundle mtime is a proxy — it gets touched whenever the auto-updater swaps the binary." "browser.version_currency"
    else
      warn "Browser bundle(s) >28d stale: ${STALE_BROWSERS[*]}" "Launch each to trigger the built-in auto-updater, or 'brew upgrade --cask <name>' if installed that way. Stale Chromium / Firefox = unpatched CVEs on every page render. Bundle mtime is a proxy — it gets touched whenever the auto-updater swaps the binary." "browser.version_currency"
    fi
  fi

  # browser.profile_count — purely informational signal that the user has
  # already adopted some form of profile-level isolation (e.g. "Work"
  # profile vs. "Personal" vs. "Wallet"). Profiles are not a strong
  # security boundary — extensions can be installed per-profile, but the
  # underlying OS user and keychain are shared — yet a multi-profile
  # setup is a strong tell that the user has thought about isolation
  # and lowers the leverage of further nudges.
  #
  # Chromium derivatives all use the same on-disk layout: each profile
  # is a directory named "Default" or "Profile <N>" under the User Data
  # root, identifiable by the presence of a Preferences file. We count
  # those directories. Firefox uses random-suffix dirs under
  # ~/Library/Application Support/Firefox/Profiles/ — we count direct
  # children of Profiles/.
  PROFILE_COUNT_TOTAL=0
  PROFILE_COUNT_BREAKDOWN=()
  CHROMIUM_PROFILE_ROOTS=(
    "Brave|$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
    "Chrome|$HOME/Library/Application Support/Google/Chrome"
    "Edge|$HOME/Library/Application Support/Microsoft Edge"
  )
  for row in "${CHROMIUM_PROFILE_ROOTS[@]}"; do
    brand="${row%%|*}"
    root="${row##*|}"
    [[ -d "$root" ]] || continue
    count=0
    if [[ -f "$root/Default/Preferences" ]]; then
      count=$((count + 1))
    fi
    while IFS= read -r p; do
      [[ -n "$p" ]] && count=$((count + 1))
    done < <(find "$root" -maxdepth 1 -type d -name 'Profile *' 2>/dev/null)
    if ((count > 0)); then
      PROFILE_COUNT_TOTAL=$((PROFILE_COUNT_TOTAL + count))
      PROFILE_COUNT_BREAKDOWN+=("${brand}:${count}")
    fi
  done
  # Firefox.
  FIREFOX_PROFILES_DIR="$HOME/Library/Application Support/Firefox/Profiles"
  if [[ -d "$FIREFOX_PROFILES_DIR" ]]; then
    ff_count=0
    while IFS= read -r p; do
      [[ -n "$p" ]] && ff_count=$((ff_count + 1))
    done < <(find "$FIREFOX_PROFILES_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    if ((ff_count > 0)); then
      PROFILE_COUNT_TOTAL=$((PROFILE_COUNT_TOTAL + ff_count))
      PROFILE_COUNT_BREAKDOWN+=("Firefox:${ff_count}")
    fi
  fi
  if ((PROFILE_COUNT_TOTAL == 0)); then
    skip "Browser profiles: none enumerable (no Chromium / Firefox data dirs found)" "" "browser.profile_count"
  elif ((PROFILE_COUNT_TOTAL == 1)); then
    if [[ "$REDACT" == "true" ]]; then
      skip "Single browser profile in use" "Consider creating a second profile to separate wallet / sensitive logins from everyday browsing. Same browser binary, separate cookie jar, separate extension set." "browser.profile_count"
    else
      skip "Single browser profile in use (${PROFILE_COUNT_BREAKDOWN[*]})" "Consider creating a second profile to separate wallet / sensitive logins from everyday browsing. Same browser binary, separate cookie jar, separate extension set." "browser.profile_count"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      pass "Multiple browser profiles in use (${PROFILE_COUNT_TOTAL} total)" "browser.profile_count"
    else
      pass "Multiple browser profiles in use: ${PROFILE_COUNT_BREAKDOWN[*]}" "browser.profile_count"
    fi
  fi

  _check_browser_remote_debugging
  _check_browser_password_autofill
}

_check_browser_password_autofill() {
  # browser.password_autofill — for each detected Chromium-based browser
  # profile (Chrome / Brave / Edge / Arc), grep the Preferences file for
  # the native password-manager and autofill settings:
  #   - "credentials_enable_service": false → password manager OFF (pass-equivalent)
  #   - "autofill.credit_card_enabled": false → autofill cards OFF
  # When credentials_enable_service is true (the Chromium default), the
  # browser-native password manager autofills site logins. A phishing
  # site that mimics a wallet exchange URL (coinbase-login.tld) can
  # trigger that autofill. The recommended posture is to disable the
  # native password manager and use 1Password / Bitwarden as the only
  # autofill source.
  #
  # JSONC-not-required-here: Chromium Preferences is strict JSON without
  # comments, but we use grep anyway for portability. The keys are
  # well-known and stable.
  local CHROMIUM_PROFILE_ROOTS=(
    "Brave|$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
    "Chrome|$HOME/Library/Application Support/Google/Chrome"
    "Edge|$HOME/Library/Application Support/Microsoft Edge"
    "Arc|$HOME/Library/Application Support/Arc/User Data"
  )
  local AUTOFILL_ENABLED=() AUTOFILL_CHECKED=0
  local row brand root pref_files pref brand_profile
  for row in "${CHROMIUM_PROFILE_ROOTS[@]}"; do
    brand="${row%%|*}"
    root="${row##*|}"
    [[ -d "$root" ]] || continue
    # Collect Preferences files across Default + Profile N
    pref_files=()
    [[ -f "$root/Default/Preferences" ]] && pref_files+=("$root/Default/Preferences")
    while IFS= read -r pref; do
      [[ -n "$pref" ]] && pref_files+=("$pref")
    done < <(find "$root" -maxdepth 2 -type f -name 'Preferences' -path '*/Profile */Preferences' 2>/dev/null)
    for pref in ${pref_files[@]+"${pref_files[@]}"}; do
      AUTOFILL_CHECKED=$((AUTOFILL_CHECKED + 1))
      brand_profile="${brand}:$(basename "$(dirname "$pref")")"
      # Explicit `false` → disabled. Any other state (true / absent) →
      # default-on. Chromium defaults to enabled, so absence is enabled.
      if grep -qE '"credentials_enable_service"[[:space:]]*:[[:space:]]*false' "$pref" 2>/dev/null; then
        :
      else
        AUTOFILL_ENABLED+=("$brand_profile")
      fi
    done
  done
  if [[ "$AUTOFILL_CHECKED" -eq 0 ]]; then
    skip "No Chromium browser profiles found to check autofill" "" "browser.password_autofill"
    return
  fi
  if [[ ${#AUTOFILL_ENABLED[@]} -eq 0 ]]; then
    pass "Browser native password manager / autofill disabled across all checked profiles ($AUTOFILL_CHECKED)" "browser.password_autofill"
    return
  fi
  if [[ "$REDACT" == "true" ]]; then
    skip "${#AUTOFILL_ENABLED[@]} of $AUTOFILL_CHECKED browser profile(s) have native password manager / autofill enabled (Chromium default)" "A phishing site mimicking a wallet-exchange URL can trigger autofill of saved logins. Disable the native password manager and use 1Password / Bitwarden as the sole autofill source. Per browser: Settings → Autofill → Passwords → 'Offer to save passwords' off." "browser.password_autofill"
  else
    skip "Browser native password manager enabled: ${AUTOFILL_ENABLED[*]} ($AUTOFILL_CHECKED profile(s) checked)" "A phishing site mimicking a wallet-exchange URL can trigger autofill of saved logins. Disable the native password manager and use 1Password / Bitwarden as the sole autofill source. Per browser: Settings → Autofill → Passwords → 'Offer to save passwords' off." "browser.password_autofill"
  fi
}

_check_browser_remote_debugging() {
  # browser.remote_debugging — flag the `--remote-debugging-port` flag
  # being attached to any Chromium browser or Electron app. With this
  # flag the browser exposes the Chrome DevTools Protocol on a TCP
  # socket; anything that can connect to that socket (including
  # localhost-bound services on a shared dev box, or a malicious page in
  # another tab via DNS-rebinding) can dump cookies, extract session
  # tokens, intercept wallet popups, and execute JS in any open tab.
  # This is the documented technique behind multiple 2024 crypto-drainer
  # incidents.
  #
  # We surface three signals:
  #   1. A running process with the flag (FAIL — actively exposed).
  #   2. The flag in a user LaunchAgent (WARN — exposed at next login).
  #   3. The flag in a shell rc or VS Code / Cursor command-line config
  #      (WARN — exposed whenever the user starts the browser/IDE that way).
  local BROWSER_PROC_PATTERN='(Google Chrome|Brave Browser|Microsoft Edge|Chromium|Arc|Vivaldi|Opera|Visual Studio Code|Cursor|Electron)'
  local PS_OUT="" running_hits=() line
  if command -v ps >/dev/null 2>&1; then
    PS_OUT=$(ps -axwwo command= 2>/dev/null || true)
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      case "$line" in
      *--remote-debugging-port=* | *--remote-debugging-pipe* | *--inspect-brk=* | *--inspect=*)
        if echo "$line" | grep -qE "$BROWSER_PROC_PATTERN"; then
          # Extract just the leading binary name for the report
          local app
          app=$(echo "$line" | grep -oE "$BROWSER_PROC_PATTERN" | head -1)
          [[ -n "$app" ]] && running_hits+=("$app")
        fi
        ;;
      esac
    done <<<"$PS_OUT"
  fi
  # Dedupe running hits.
  local seen_run="" item dedup_run=()
  for item in ${running_hits[@]+"${running_hits[@]}"}; do
    case " $seen_run " in
    *" $item "*) ;;
    *)
      seen_run="$seen_run $item"
      dedup_run+=("$item")
      ;;
    esac
  done
  # Persisted: grep LaunchAgents and shell rc files.
  local persisted_hits=() f
  for f in "$HOME"/Library/LaunchAgents/*.plist; do
    [[ -f "$f" ]] || continue
    if grep -qE -- '--remote-debugging-port' "$f" 2>/dev/null; then
      persisted_hits+=("$(basename "$f")")
    fi
  done
  for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.zprofile" "$HOME/.profile" "$HOME/.bash_profile"; do
    [[ -f "$f" ]] || continue
    if grep -qE -- '--remote-debugging-port' "$f" 2>/dev/null; then
      persisted_hits+=("$(basename "$f")")
    fi
  done
  if [[ ${#dedup_run[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      fail "${#dedup_run[@]} browser/Electron process(es) running with --remote-debugging-port" "Anyone who can connect to the debug socket can dump cookies, extract session tokens, intercept wallet popups, and execute JS in any tab. Quit the process and relaunch without the flag. If you need it for development, bind to a non-default port and run only in a throwaway profile." "browser.remote_debugging"
    else
      fail "Browser/Electron with --remote-debugging-port: ${dedup_run[*]}" "Anyone who can connect to the debug socket can dump cookies, extract session tokens, intercept wallet popups, and execute JS in any tab. Quit the process and relaunch without the flag. If you need it for development, bind to a non-default port and run only in a throwaway profile." "browser.remote_debugging"
    fi
    return
  fi
  if [[ ${#persisted_hits[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "${#persisted_hits[@]} config file(s) reference --remote-debugging-port" "Not currently running, but launching the configured browser/script will reopen the debug surface. Review the LaunchAgent or shell rc and remove the flag." "browser.remote_debugging"
    else
      warn "--remote-debugging-port referenced in: ${persisted_hits[*]}" "Not currently running, but launching the configured browser/script will reopen the debug surface. Review the LaunchAgent or shell rc and remove the flag." "browser.remote_debugging"
    fi
    return
  fi
  pass "No browsers running or configured with --remote-debugging-port" "browser.remote_debugging"
}

section_10_browser_extensions() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 10 · Browser Extensions (security-relevant)
  # ═════════════════════════════════════════════════════════════════════════════
  section "10 · Browser Extensions"

  # Parallel arrays for bash 3.2 compatibility (no associative arrays).
  PROTECTIVE_NAMES=("uBlock Origin" "uBlock Origin Lite" "1Password" "Bitwarden" "Privacy Badger" "DuckDuckGo Privacy Essentials")
  PROTECTIVE_IDS=("cjpalhdlnbpafiamejdnhcphjbkeiagm" "ddkjiahejlhfcafbddmgiahcphecmpfh" "aeblfdkhhhdcdjpifhhbdiojplfjncoa" "nngceckbapebfimnlniiiahkandclblb" "pkehgijcmpdhfbdbbnkijodmdjhbjlgp" "bkdgflcldnnnapblkhphbgpggdiikppg")
  WALLET_NAMES=("MetaMask" "Phantom" "Rabby")
  WALLET_IDS=("nkbihfbeogaeaoehlefnkodbefgpgknn" "bfnaelmomeimhlpmgjnjophhpkkoljpa" "acmacodkjbdgmoleebolmdjonilkdbch")

  PROTECTIVE_FOUND=()
  WALLET_FOUND=()
  for i in "${!PROTECTIVE_NAMES[@]}"; do
    in=$(detect_ext_in_chromium "${PROTECTIVE_IDS[$i]}")
    [[ -n "$in" ]] && PROTECTIVE_FOUND+=("${PROTECTIVE_NAMES[$i]} → $in")
  done
  for i in "${!WALLET_NAMES[@]}"; do
    in=$(detect_ext_in_chromium "${WALLET_IDS[$i]}")
    [[ -n "$in" ]] && WALLET_FOUND+=("${WALLET_NAMES[$i]} → $in")
  done
  WG_IN=$(detect_ext_in_chromium "bdkffjgegfgmlhgjcoanlhcfopdmfldn")
  [[ -z "$WG_IN" ]] && WG_IN=$(detect_ext_by_name "Wallet[[:space:]]?Guard")
  PU_IN=$(detect_ext_in_chromium "haochjmjpckieojlnfmgkihppmnpgglk")
  [[ -z "$PU_IN" ]] && PU_IN=$(detect_ext_by_name "Pocket[[:space:]]?Universe")

  if [[ ${#PROTECTIVE_FOUND[@]} -gt 0 ]]; then
    pass "Protective extensions present:" "ext.protective"
    if [[ "$MODE" != "json" && "$REDACT" != "true" ]]; then
      for r in "${PROTECTIVE_FOUND[@]}"; do printf "          %s· %s%s\n" "$DIM" "$r" "$NC"; done
    fi
  else
    warn "No protective extensions detected (uBlock / Privacy Badger / DDG)" "Install at minimum: uBlock Origin" "ext.protective"
  fi

  if [[ ${#WALLET_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "${#WALLET_FOUND[@]} wallet extension(s) installed" "If on main user, migrate to vault user (plan §6.2). Wallet exposure on main account is the biggest crypto-specific risk." "ext.wallet"
    else
      warn "Wallet extension(s) installed: ${WALLET_FOUND[*]}" "If on main user, migrate to vault user (plan §6.2). Wallet exposure on main account is the biggest crypto-specific risk." "ext.wallet"
    fi
    # Detect specific wallets to give wallet-aware simulator guidance.
    # The outer test guarantees the array is non-empty.
    HAS_RABBY=false
    HAS_METAMASK=false
    for entry in "${WALLET_FOUND[@]}"; do
      [[ "$entry" == Rabby* ]] && HAS_RABBY=true
      [[ "$entry" == MetaMask* ]] && HAS_METAMASK=true
    done

    if [[ -z "$WG_IN" && -z "$PU_IN" ]]; then
      if [[ "$REDACT" == "true" ]]; then
        if $HAS_RABBY; then
          pass "No external simulator detected; wallet has built-in transaction simulation" "ext.simulator.advice"
        else
          warn "No external transaction simulator detected" "Install one alongside your wallet — catches malicious approvals before signing." "ext.simulator.advice"
        fi
      elif $HAS_METAMASK; then
        warn "No external transaction simulator, and MetaMask is installed" "MetaMask's built-in preview is weak. Install Wallet Guard or Pocket Universe — they catch off-chain (EIP-712 / Permit) drain attacks MetaMask alone misses." "ext.simulator.advice"
      elif $HAS_RABBY; then
        pass "No external simulator — but Rabby has solid built-in transaction simulation" "ext.simulator.advice"
        skip "Optional: add Wallet Guard or Pocket Universe for extra EIP-712 / Permit coverage" "Rabby covers ~90% of on-chain cases. External simulators add belt-and-suspenders for off-chain signature drainers." "ext.simulator.optional"
      else
        warn "No transaction simulator (Wallet Guard / Pocket Universe) detected" "Install one alongside your wallet — catches malicious approvals before signing" "ext.simulator.advice"
      fi
    else
      if [[ "$REDACT" == "true" ]]; then
        [[ -n "$WG_IN" ]] && pass "Transaction simulator extension installed" "ext.simulator.walletguard"
        [[ -n "$PU_IN" ]] && pass "Transaction simulator extension installed" "ext.simulator.pocketuniverse"
      else
        [[ -n "$WG_IN" ]] && pass "Wallet Guard installed in: $WG_IN" "ext.simulator.walletguard"
        [[ -n "$PU_IN" ]] && pass "Pocket Universe installed in: $PU_IN" "ext.simulator.pocketuniverse"
      fi
    fi
  else
    pass "No wallet extension detected in this user account" "ext.wallet"
  fi

  # Total Chromium extensions (hygiene)
  TOTAL_EXT=0
  for root in \
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" \
    "$HOME/Library/Application Support/Google/Chrome"; do
    [[ -d "$root" ]] || continue
    for prof in "$root"/Default "$root"/Profile*; do
      [[ -d "$prof/Extensions" ]] || continue
      n=$(find "$prof/Extensions" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
      n=${n:-0}
      TOTAL_EXT=$((TOTAL_EXT + n))
    done
  done
  if [[ "$TOTAL_EXT" -gt 0 ]]; then
    if [[ "$TOTAL_EXT" -le 10 ]]; then
      pass "Chromium browsers have $TOTAL_EXT extensions installed (lean)" "ext.total.count"
    elif [[ "$TOTAL_EXT" -le 20 ]]; then
      warn "Chromium browsers have $TOTAL_EXT extensions installed" "Audit and remove unused — every extension is attack surface" "ext.total.count"
    else
      warn "Chromium browsers have $TOTAL_EXT extensions installed (high)" "Aggressive audit recommended; especially in the wallet/vault profile" "ext.total.count"
    fi
  fi

  # Safari extensions — pluginkit enumerates host-app extensions including
  # Safari. Names are surfaced verbatim; we re-classify by substring against
  # the same protective/wallet/simulator lists used above.
  SAFARI_EXT_DUMP=""
  if command -v pluginkit >/dev/null 2>&1; then
    SAFARI_EXT_DUMP=$(pluginkit -mAvvv 2>/dev/null | grep -i "com.apple.Safari.extension" || true)
  fi
  SAFARI_PROTECTIVE=()
  SAFARI_WALLET=()
  if [[ -n "$SAFARI_EXT_DUMP" ]]; then
    for kw in "uBlock" "1Password" "Bitwarden" "Privacy Badger" "DuckDuckGo"; do
      if echo "$SAFARI_EXT_DUMP" | grep -qi "$kw"; then
        SAFARI_PROTECTIVE+=("$kw")
      fi
    done
    for kw in "MetaMask" "Phantom" "Rabby" "Coinbase" "Ledger"; do
      if echo "$SAFARI_EXT_DUMP" | grep -qi "$kw"; then
        SAFARI_WALLET+=("$kw")
      fi
    done
    SAFARI_EXT_COUNT=$(echo "$SAFARI_EXT_DUMP" | wc -l | tr -d ' ')
    if [[ ${#SAFARI_WALLET[@]} -gt 0 ]]; then
      if [[ "$REDACT" == "true" ]]; then
        warn "${#SAFARI_WALLET[@]} Safari wallet extension(s) detected" "Wallet exposure on the same browser used for general browsing is the highest crypto-specific risk." "ext.safari.wallet"
      else
        warn "Safari wallet extension(s): ${SAFARI_WALLET[*]}" "Wallet exposure on the same browser used for general browsing is the highest crypto-specific risk." "ext.safari.wallet"
      fi
    fi
    if [[ ${#SAFARI_PROTECTIVE[@]} -gt 0 ]]; then
      if [[ "$REDACT" == "true" ]]; then
        pass "${#SAFARI_PROTECTIVE[@]} Safari protective extension(s) detected" "ext.safari.protective"
      else
        pass "Safari protective extension(s): ${SAFARI_PROTECTIVE[*]}" "ext.safari.protective"
      fi
    fi
    skip "Safari has $SAFARI_EXT_COUNT extension(s) registered with pluginkit" "Audit: Safari → Settings → Extensions. Each extension can read pages it has been granted access to." "ext.safari.total"
  fi

  # Firefox extensions — parse extensions.json conservatively with stock text
  # tools. This is intentionally not a full JSON parser; it extracts enough
  # extension display names for posture classification without pulling in
  # python3 (which can trigger an Xcode CLT install prompt on fresh macOS).
  FF_PROFILES_ROOT="$HOME/Library/Application Support/Firefox/Profiles"
  if [[ -d "$FF_PROFILES_ROOT" ]]; then
    FF_EXT_DUMP=""
    while IFS= read -r ff_json; do
      [[ -f "$ff_json" ]] || continue
      names=$(grep -E '"name"[[:space:]]*:' "$ff_json" 2>/dev/null | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' | grep -v '^$' || true)
      [[ -n "$names" ]] && FF_EXT_DUMP="${FF_EXT_DUMP}${FF_EXT_DUMP:+
}${names}"
    done < <(find "$FF_PROFILES_ROOT" -name extensions.json -type f 2>/dev/null)
    FF_PROTECTIVE=()
    FF_WALLET=()
    if [[ -n "$FF_EXT_DUMP" ]]; then
      for kw in "uBlock" "1Password" "Bitwarden" "Privacy Badger" "DuckDuckGo"; do
        if echo "$FF_EXT_DUMP" | grep -qi "$kw"; then
          FF_PROTECTIVE+=("$kw")
        fi
      done
      for kw in "MetaMask" "Phantom" "Rabby" "Coinbase" "Ledger"; do
        if echo "$FF_EXT_DUMP" | grep -qi "$kw"; then
          FF_WALLET+=("$kw")
        fi
      done
      FF_EXT_COUNT=$(echo "$FF_EXT_DUMP" | grep -c '.' || true)
      FF_EXT_COUNT=${FF_EXT_COUNT:-0}
      if [[ ${#FF_WALLET[@]} -gt 0 ]]; then
        if [[ "$REDACT" == "true" ]]; then
          warn "${#FF_WALLET[@]} Firefox wallet extension(s) detected" "Move wallet to a dedicated browser/profile that you don't use for general web browsing." "ext.firefox.wallet"
        else
          warn "Firefox wallet extension(s): ${FF_WALLET[*]}" "Move wallet to a dedicated browser/profile that you don't use for general web browsing." "ext.firefox.wallet"
        fi
      fi
      if [[ ${#FF_PROTECTIVE[@]} -gt 0 ]]; then
        if [[ "$REDACT" == "true" ]]; then
          pass "${#FF_PROTECTIVE[@]} Firefox protective extension(s) detected" "ext.firefox.protective"
        else
          pass "Firefox protective extension(s): ${FF_PROTECTIVE[*]}" "ext.firefox.protective"
        fi
      fi
      skip "Firefox has $FF_EXT_COUNT extension(s) across all profiles" "Audit: about:addons. Disable anything you no longer use." "ext.firefox.total"
    fi
  fi

}

_check_ssh_config_risky_options() {
  # ssh.config.risky_options — flag dangerous patterns in ~/.ssh/config
  # that apply globally (top-level scope before any `Host` block) or to
  # `Host *` (wildcard matches every host).
  #
  # Patterns we flag:
  #   - ForwardAgent yes        : exposes the local 1Password / ssh-agent
  #                               socket to every server you SSH into. A
  #                               compromised destination steals all keys.
  #   - StrictHostKeyChecking no: accepts any host key on first connect;
  #                               defeats MITM detection.
  #   - UserKnownHostsFile /dev/null : same as above, plus discards the
  #                                    record so subsequent MITMs aren't
  #                                    flagged either.
  #
  # Scope-aware parsing: we walk the file line-by-line and track whether
  # we're currently inside `Host *` / `Match all` / global (pre-Host)
  # scope. Per-host blocks (`Host github.com`) are intentionally NOT
  # flagged — `ForwardAgent yes` under `Host trusted.internal.example`
  # is a defensible setup.
  local cfg="$HOME/.ssh/config"
  if [[ ! -f "$cfg" ]]; then
    skip "~/.ssh/config not present" "" "ssh.config.risky_options"
    return
  fi
  local in_global_scope=true line stripped host_pattern issues=()
  while IFS= read -r line; do
    # Strip leading whitespace + trailing comment for matching only.
    stripped="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$stripped" || "$stripped" == \#* ]] && continue
    # Section break: a `Host` or `Match` line starts a new scope.
    if [[ "$stripped" =~ ^[Hh]ost[[:space:]]+(.*)$ ]]; then
      host_pattern="${BASH_REMATCH[1]}"
      # Whether the new section applies broadly. Two patterns:
      #   - starts with a bare `*` (e.g. "Host *", "Host * !ignored.tld")
      #   - contains ` *` somewhere (e.g. "Host alpha *" or "Host alpha *.example")
      # The second pattern with trailing `**` (zero-or-more) subsumes both
      # `… *` and `… *foo`, so we don't need a separate `*\ \*` alternative.
      case "$host_pattern" in
      \** | *\ \**) in_global_scope=true ;;
      *) in_global_scope=false ;;
      esac
      continue
    fi
    if [[ "$stripped" =~ ^[Mm]atch[[:space:]]+all([[:space:]]|$) ]]; then
      in_global_scope=true
      continue
    fi
    if [[ "$stripped" =~ ^[Mm]atch[[:space:]]+ ]]; then
      in_global_scope=false
      continue
    fi
    $in_global_scope || continue
    # Inside global / Host * / Match all scope — check for risky options.
    case "$stripped" in
    [Ff]orward[Aa]gent[[:space:]]*[Yy][Ee][Ss]*)
      issues+=("ForwardAgent yes")
      ;;
    [Ss]trict[Hh]ost[Kk]ey[Cc]hecking[[:space:]]*[Nn][Oo]*)
      issues+=("StrictHostKeyChecking no")
      ;;
    *[Uu]ser[Kk]nown[Hh]osts[Ff]ile[[:space:]]*/dev/null*)
      issues+=("UserKnownHostsFile /dev/null")
      ;;
    esac
  done <"$cfg"
  if [[ ${#issues[@]} -eq 0 ]]; then
    pass "~/.ssh/config has no risky global / Host * options" "ssh.config.risky_options"
    return
  fi
  # Dedupe (a setting might appear in both global and Host *).
  local seen="" issue dedup=()
  for issue in "${issues[@]}"; do
    case " $seen " in
    *" $issue "*) ;;
    *)
      seen="$seen $issue"
      dedup+=("$issue")
      ;;
    esac
  done
  if [[ "$REDACT" == "true" ]]; then
    warn "${#dedup[@]} risky option(s) in global / Host * scope of ~/.ssh/config" "Each applies to every host you SSH into. ForwardAgent yes exposes your 1Password/ssh-agent socket to compromise on any destination; StrictHostKeyChecking no defeats MITM detection; UserKnownHostsFile /dev/null discards the record so subsequent MITMs aren't flagged either. Move these into per-host blocks if you actually need them." "ssh.config.risky_options"
  else
    warn "Risky options in global / Host * scope of ~/.ssh/config: ${dedup[*]}" "Each applies to every host you SSH into. ForwardAgent yes exposes your 1Password/ssh-agent socket to compromise on any destination; StrictHostKeyChecking no defeats MITM detection; UserKnownHostsFile /dev/null discards the record so subsequent MITMs aren't flagged either. Move these into per-host blocks if you actually need them." "ssh.config.risky_options"
  fi
}

section_11_ssh() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 11 · SSH Keys & Agent
  # ═════════════════════════════════════════════════════════════════════════════
  section "11 · SSH Keys & Agent"

  # SSH private keys — distinguish unencrypted (real risk) from passphrase-protected (safer).
  # Scope `nullglob` to this section: shopt flags are process-global, so an
  # unset would leak into every section that runs after §11 (e.g. §13/§17/§22
  # glob loops would silently see unmatched globs disappear instead of becoming
  # literal — the opposite of what those sections were written for).
  UNENCRYPTED_KEYS=()
  ENCRYPTED_KEYS=()
  UNKNOWN_KEYS=()
  _had_nullglob=0
  shopt -q nullglob && _had_nullglob=1
  shopt -s nullglob 2>/dev/null || true
  for k in "$HOME"/.ssh/id_rsa "$HOME"/.ssh/id_ed25519 "$HOME"/.ssh/id_ecdsa "$HOME"/.ssh/id_dsa; do
    [[ -f "$k" ]] || continue
    # ssh-keygen -y -P '' tries to read the public half with empty passphrase.
    # Succeeds only if the key is unencrypted.
    SSH_KEYGEN_STATUS=0
    SSH_KEYGEN_ERR=$(ssh-keygen -y -P "" -f "$k" 2>&1 >/dev/null) || SSH_KEYGEN_STATUS=$?
    if [[ "$SSH_KEYGEN_STATUS" -eq 0 ]]; then
      UNENCRYPTED_KEYS+=("$(basename "$k")")
    elif echo "$SSH_KEYGEN_ERR" | grep -qi "incorrect passphrase"; then
      ENCRYPTED_KEYS+=("$(basename "$k")")
    else
      UNKNOWN_KEYS+=("$(basename "$k")")
    fi
  done
  if [[ ${#UNENCRYPTED_KEYS[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "Unencrypted SSH private key(s) on disk: ${#UNENCRYPTED_KEYS[@]}" "Move keys to an external SSH agent, or add a passphrase: ssh-keygen -p -f ~/.ssh/<keyfile>" "ssh.keys.unencrypted"
    else
      warn "Unencrypted SSH private key(s) on disk: ${UNENCRYPTED_KEYS[*]}" "Migrate to 1Password SSH agent / Secretive, OR add a passphrase: ssh-keygen -p -f ~/.ssh/<keyfile>" "ssh.keys.unencrypted"
    fi
  fi
  if [[ ${#ENCRYPTED_KEYS[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "SSH private key(s) appear passphrase-protected: ${#ENCRYPTED_KEYS[@]}" "ssh.keys.encrypted"
    else
      pass "SSH private key(s) appear passphrase-protected: ${ENCRYPTED_KEYS[*]}" "ssh.keys.encrypted"
    fi
  fi
  if [[ ${#UNKNOWN_KEYS[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "SSH private key(s) could not be classified: ${#UNKNOWN_KEYS[@]}" "Inspect manually; ssh-keygen could not read these keys for a reason other than an incorrect empty passphrase." "ssh.keys.unknown"
    else
      warn "SSH private key(s) could not be classified: ${UNKNOWN_KEYS[*]}" "Inspect manually; ssh-keygen could not read these keys for a reason other than an incorrect empty passphrase." "ssh.keys.unknown"
    fi
  fi
  if [[ ${#UNENCRYPTED_KEYS[@]} -eq 0 && ${#ENCRYPTED_KEYS[@]} -eq 0 && ${#UNKNOWN_KEYS[@]} -eq 0 ]]; then
    pass "No private SSH keys in ~/.ssh/" "ssh.keys.none"
  fi

  ONEP_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
  if [[ -S "$ONEP_SOCK" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "External SSH agent socket present" "ssh.agent.1password"
    else
      pass "1Password SSH agent socket present" "ssh.agent.1password"
    fi
  elif [[ -e "$ONEP_SOCK" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "External SSH agent path exists but is not a socket" "" "ssh.agent.1password"
    else
      warn "1Password agent path exists but is not a socket" "" "ssh.agent.1password"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "No external SSH agent socket detected" "Optional: use an external SSH agent so private keys do not need to sit unprotected on disk." "ssh.agent.1password"
    else
      skip "No 1Password SSH agent socket" "Optional: 1Password → Settings → Developer → Use the SSH agent" "ssh.agent.1password"
    fi
  fi

  case "${SSH_AUTH_SOCK:-}" in
  *1password*)
    if [[ "$REDACT" == "true" ]]; then
      pass "SSH_AUTH_SOCK points to an external SSH agent" "ssh.authsock"
    else
      pass "SSH_AUTH_SOCK → 1Password agent" "ssh.authsock"
    fi
    ;;
  */secretive*)
    if [[ "$REDACT" == "true" ]]; then
      pass "SSH_AUTH_SOCK points to a Secure Enclave SSH agent" "ssh.authsock"
    else
      pass "SSH_AUTH_SOCK → Secretive (Secure Enclave)" "ssh.authsock"
    fi
    ;;
  /var/run/com.apple.launchd*)
    if [[ "$REDACT" == "true" ]]; then
      warn "SSH_AUTH_SOCK points to the macOS default ssh-agent" "Point at an external SSH agent in your shell rc." "ssh.authsock"
    else
      warn "SSH_AUTH_SOCK → macOS default ssh-agent" "Point at 1Password or Secretive in your shell rc" "ssh.authsock"
    fi
    ;;
  "") skip "SSH_AUTH_SOCK is unset in this shell" "" "ssh.authsock" ;;
  *) skip "SSH_AUTH_SOCK: $(redact path "${SSH_AUTH_SOCK}")" "" "ssh.authsock" ;;
  esac

  if [[ -f "$HOME/.ssh/config" ]] && grep -qiE "IdentityAgent.*1password|IdentityAgent.*secretive" "$HOME/.ssh/config"; then
    pass "~/.ssh/config has IdentityAgent → external agent" "ssh.config.identityagent"
  elif [[ -f "$HOME/.ssh/config" ]] && grep -qi "IdentityAgent" "$HOME/.ssh/config"; then
    skip "~/.ssh/config has a custom IdentityAgent" "" "ssh.config.identityagent"
  else
    skip "~/.ssh/config has no IdentityAgent line" "" "ssh.config.identityagent"
  fi

  if [[ -f "$HOME/.ssh/config" ]]; then
    PERMS=$(stat -f "%Lp" "$HOME/.ssh/config" 2>/dev/null || echo "?")
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
      pass "~/.ssh/config permissions are tight ($PERMS)" "ssh.config.perms"
    else
      warn "~/.ssh/config permissions: $PERMS" "Run: chmod 600 ~/.ssh/config" "ssh.config.perms"
    fi
  fi

  _check_ssh_config_risky_options

  # Composite: SSH key risk surface.
  # Unencrypted private keys on disk are a liability; an external agent
  # (1Password / Secretive) mitigates the risk because the key never
  # leaves the agent's control. Combine the key state with the agent
  # state to produce a single posture verdict.
  no_keys=$(_status_of "ssh.keys.none")
  unenc=$(_status_of "ssh.keys.unencrypted")
  enc=$(_status_of "ssh.keys.encrypted")
  agent=$(_status_of "ssh.agent.1password")
  authsock=$(_status_of "ssh.authsock")
  ext_agent=false
  [[ "$agent" == "pass" || "$authsock" == "pass" ]] && ext_agent=true
  # Accept both warn and fail for ssh.keys.unencrypted: under --profile=web3
  # or --profile=paranoid, the row is rewritten warn → fail by _apply_profile,
  # which is exactly the case this composite is most meant to catch. Reading
  # `== "warn"` only would let the composite go silent and fall through to a
  # misleading "encrypted keys with external agent" PASS — the worst outcome
  # for a user who explicitly opted into the stricter profile.
  if [[ "$no_keys" == "pass" ]]; then
    pass "SSH posture: no on-disk private keys" "ssh.posture"
  elif [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && ! $ext_agent; then
    if [[ "$REDACT" == "true" ]]; then
      fail "SSH posture: unencrypted on-disk keys with no external agent" "Either add a passphrase ('ssh-keygen -p -f ~/.ssh/<key>') or move to an external SSH agent so the key never leaves the agent." "ssh.posture"
    else
      fail "SSH posture: unencrypted on-disk keys with no external agent" "Either add a passphrase ('ssh-keygen -p -f ~/.ssh/<key>') or move to 1Password / Secretive SSH agent so the key never leaves the agent." "ssh.posture"
    fi
  elif [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && $ext_agent; then
    warn "SSH posture: unencrypted keys still on disk despite external agent" "Add a passphrase to the on-disk key, or remove it entirely if the agent already holds the equivalent." "ssh.posture"
  elif [[ "$enc" == "pass" ]] && ! $ext_agent; then
    if [[ "$REDACT" == "true" ]]; then
      warn "SSH posture: encrypted keys but no external agent — passphrase entry on every use" "Optional improvement: use an external SSH agent so the key is unlocked once per session." "ssh.posture"
    else
      warn "SSH posture: encrypted keys but no external agent — passphrase entry on every use" "Optional improvement: 1Password SSH agent or Secretive (Secure Enclave) so the key is unlocked once per session." "ssh.posture"
    fi
  else
    pass "SSH posture: encrypted keys with external agent" "ssh.posture"
  fi

  # Restore caller's nullglob state (see top of section for rationale).
  ((_had_nullglob)) || shopt -u nullglob 2>/dev/null || true
}

section_12_git_signing() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 12 · Git Signing & Commit Verification
  # ═════════════════════════════════════════════════════════════════════════════
  section "12 · Git Signing & Commit Verification"

  if command -v git >/dev/null 2>&1; then
    SIGN=$(git config --global commit.gpgsign 2>/dev/null || echo "")
    FMT=$(git config --global gpg.format 2>/dev/null || echo "")
    KEY=$(git config --global user.signingkey 2>/dev/null || echo "")
    ALLOWED=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")

    if [[ "$SIGN" == "true" ]] && [[ "$FMT" == "ssh" ]] && [[ -n "$KEY" ]]; then
      pass "Git commit signing: enabled, SSH-based, signing key set" "git.signing.enabled"
      if [[ -n "$ALLOWED" ]] && [[ -f "${ALLOWED/#\~/$HOME}" ]]; then
        pass "git allowedSignersFile present: $(redact path "$ALLOWED")" "git.signing.allowedsigners"
      else
        warn "git gpg.ssh.allowedSignersFile not set or missing" "Set: git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers" "git.signing.allowedsigners"
      fi
    elif [[ "$SIGN" == "true" ]] && [[ "$FMT" == "ssh" ]]; then
      warn "Git SSH signing enabled but no user.signingkey set" "git config --global user.signingkey 'ssh-ed25519 AAAA...'" "git.signing.enabled"
    elif [[ "$SIGN" == "true" ]]; then
      warn "Git commit signing enabled (format: ${FMT:-default GPG})" "Consider switching to SSH-based: git config --global gpg.format ssh (works with 1Password / Secretive)" "git.signing.enabled"
    else
      warn "Git commit signing not enabled" "Required for §6.5a 'signed commits' branch protection" "git.signing.enabled"
    fi

    GIT_EMAIL=$(git config --global user.email 2>/dev/null || echo "")
    if [[ -n "$GIT_EMAIL" ]]; then
      pass "Git user.email is set ($(redact email "$GIT_EMAIL"))" "git.email.set"
    else
      warn "Git user.email is not set globally" "git config --global user.email 'you@example.com'" "git.email.set"
    fi
  else
    skip "git not installed" "" "git.installed"
  fi

}

_check_supply_direnv() {
  # direnv stores per-path approvals as one file each under
  # ~/.local/share/direnv/allow/. Each approved .envrc executes its
  # contents in the user's shell when the user `cd`s into the matching
  # directory. Long-stale allow lists accumulate cruft and widen the
  # attack surface: a stale allow for an old repo that's since been
  # compromised auto-executes on entry. Count entries and emit
  # advisory thresholds.
  local DIRENV_ALLOW_DIR="$HOME/.local/share/direnv/allow"
  if [[ ! -d "$DIRENV_ALLOW_DIR" ]]; then
    skip "direnv not in use (no allow list directory)" "" "supply.direnv.allow_list"
    return
  fi
  local DIRENV_ALLOW_COUNT
  DIRENV_ALLOW_COUNT=$(find "$DIRENV_ALLOW_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
  DIRENV_ALLOW_COUNT=${DIRENV_ALLOW_COUNT:-0}
  if [[ "$DIRENV_ALLOW_COUNT" -eq 0 ]]; then
    pass "direnv allow list is empty" "supply.direnv.allow_list"
  elif [[ "$DIRENV_ALLOW_COUNT" -le 20 ]]; then
    skip "${DIRENV_ALLOW_COUNT} direnv-approved .envrc path(s)" "Each entry is a directory whose .envrc auto-executes in your shell when you cd into it. Periodically: 'direnv prune' (removes orphaned entries), then review the rest." "supply.direnv.allow_list"
  else
    warn "${DIRENV_ALLOW_COUNT} direnv-approved .envrc path(s) — review for stale entries" "Each entry is a directory whose .envrc auto-executes in your shell. Run 'direnv prune' to remove orphaned entries (referenced repos no longer on disk), then review the rest manually: ls -lt $DIRENV_ALLOW_DIR | head" "supply.direnv.allow_list"
  fi
}

_check_supply_pip_extra_index() {
  # When pip is configured with extra-index-url, it pulls from a
  # secondary index in addition to PyPI. If a private package name
  # collides with a public PyPI package, the public one wins by default
  # — the classic "dependency confusion" attack pattern. Surface any
  # configured extra-index-url so the user can review.
  local PIP_CONFIG_PATHS=(
    "$HOME/.pip/pip.conf"
    "$HOME/.config/pip/pip.conf"
    "$HOME/Library/Application Support/pip/pip.conf"
    "/etc/pip.conf"
  )
  local PIP_EXTRA_INDEX_HITS=() cfg any_config_found=false
  for cfg in "${PIP_CONFIG_PATHS[@]}"; do
    if [[ -f "$cfg" ]]; then
      any_config_found=true
      if grep -qE '^[[:space:]]*extra-index-url[[:space:]]*=' "$cfg" 2>/dev/null; then
        PIP_EXTRA_INDEX_HITS+=("$cfg")
      fi
    fi
  done
  if [[ ${#PIP_EXTRA_INDEX_HITS[@]} -eq 0 ]]; then
    if [[ "$any_config_found" == "true" ]]; then
      pass "No pip extra-index-url configured" "supply.pip.extra_index_url"
    else
      skip "No pip config detected" "" "supply.pip.extra_index_url"
    fi
    return
  fi
  if [[ "$REDACT" == "true" ]]; then
    warn "pip extra-index-url configured in ${#PIP_EXTRA_INDEX_HITS[@]} location(s)" "Each extra index is a parallel source for package resolution. If a private name collides with a public PyPI package, the public one wins by default — the dependency-confusion pattern. Audit the URL(s) and consider 'index-url' (replace) instead of 'extra-index-url' (add)." "supply.pip.extra_index_url"
  else
    warn "pip extra-index-url configured in: ${PIP_EXTRA_INDEX_HITS[*]}" "Each extra index is a parallel source for package resolution. If a private name collides with a public PyPI package, the public one wins by default — the dependency-confusion pattern. Audit the URL(s) and consider 'index-url' (replace) instead of 'extra-index-url' (add)." "supply.pip.extra_index_url"
  fi
}

_check_supply_uv_config() {
  # uv (Astral's Python package manager) and pixi (prefix.dev's polyglot
  # package manager) inherit the same dependency-confusion risk pattern
  # from pip. We grep for extra-index-url variants and surface
  # advisorially since the keys are still stabilising across versions.
  local UV_CONFIG_PATHS=(
    "$HOME/.config/uv/uv.toml"
    "$HOME/.config/pixi/config.toml"
  )
  local UV_HITS=() cfg any_config_found=false
  for cfg in "${UV_CONFIG_PATHS[@]}"; do
    if [[ -f "$cfg" ]]; then
      any_config_found=true
      if grep -qE '^[[:space:]]*(extra-index-url|extra_index_url|extra-index-urls|extra_index_urls)[[:space:]]*=' "$cfg" 2>/dev/null; then
        UV_HITS+=("$cfg")
      fi
    fi
  done
  if [[ ${#UV_HITS[@]} -eq 0 ]]; then
    if [[ "$any_config_found" == "true" ]]; then
      pass "No uv / pixi extra-index-url configured" "supply.uv.config"
    else
      skip "uv / pixi not configured" "" "supply.uv.config"
    fi
    return
  fi
  if [[ "$REDACT" == "true" ]]; then
    warn "uv / pixi extra-index-url configured in ${#UV_HITS[@]} location(s)" "Same dependency-confusion risk as pip extra-index-url — a private package name colliding with a public one falls back to the public registry. Audit each extra index." "supply.uv.config"
  else
    warn "uv / pixi extra-index-url configured in: ${UV_HITS[*]}" "Same dependency-confusion risk as pip extra-index-url — a private package name colliding with a public one falls back to the public registry. Audit each extra index." "supply.uv.config"
  fi
}

section_13_supply_chain() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 13 · Supply Chain (npm / yarn / pnpm)
  # ═════════════════════════════════════════════════════════════════════════════
  section "13 · Supply Chain (npm / yarn / pnpm)"

  # ignore-scripts default — single biggest knob against supply-chain worm attacks.
  if command -v npm >/dev/null 2>&1; then
    IGNORE_SCRIPTS=$(npm config get ignore-scripts 2>/dev/null | tail -1 || echo "false")
    if [[ "$IGNORE_SCRIPTS" == "true" ]]; then
      pass "npm: ignore-scripts is true (lifecycle scripts disabled by default)" "supply.npm.ignorescripts"
    else
      warn "npm: ignore-scripts is false" "npm config set ignore-scripts true" "supply.npm.ignorescripts"
    fi
  fi
  if command -v yarn >/dev/null 2>&1; then
    YARN_IGN=$(yarn config get ignore-scripts 2>/dev/null | tail -1 || echo "")
    YARN_BERRY=$(yarn config get enableScripts 2>/dev/null | tail -1 || echo "")
    if [[ "$YARN_IGN" == "true" ]] || [[ "$YARN_BERRY" == "false" ]]; then
      pass "yarn: scripts disabled by default" "supply.yarn.ignorescripts"
    else
      warn "yarn: install scripts run by default" "yarn config set ignore-scripts true (yarn 1.x) — or set 'enableScripts: false' in .yarnrc.yml (yarn 2+)" "supply.yarn.ignorescripts"
    fi
  fi
  if command -v pnpm >/dev/null 2>&1; then
    PNPM_IGN=$(pnpm config get ignore-scripts 2>/dev/null | tail -1 || echo "")
    if [[ "$PNPM_IGN" == "true" ]]; then
      pass "pnpm: ignore-scripts is true" "supply.pnpm.ignorescripts"
    else
      warn "pnpm: ignore-scripts is false" "pnpm config set ignore-scripts true" "supply.pnpm.ignorescripts"
    fi
  fi

  # Socket.dev CLI (or custom 7-day cooldown wrapper)
  SOCKET_FOUND=false
  if command -v socket >/dev/null 2>&1; then
    SOCKET_FOUND=true
  elif npm ls -g --depth=0 2>/dev/null | grep -q "@socketsecurity/cli\|socket@"; then
    SOCKET_FOUND=true
  fi

  WRAPPER_FOUND=false
  for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshenv"; do
    [[ -f "$rc" ]] || continue
    if grep -qE "_safe_install|_pkg_age_days|cooldown.*npm|npm.*cooldown" "$rc" 2>/dev/null; then
      WRAPPER_FOUND=true
      break
    fi
  done

  if $SOCKET_FOUND && $WRAPPER_FOUND; then
    pass "Supply-chain protection: Socket CLI + 7-day cooldown wrapper both present" "supply.scanner"
  elif $SOCKET_FOUND; then
    pass "Supply-chain protection: Socket CLI installed" "supply.scanner"
  elif $WRAPPER_FOUND; then
    pass "Supply-chain protection: 7-day cooldown wrapper present in shell rc" "supply.scanner"
  else
    warn "No supply-chain scanner / age-cooldown mechanism detected" "Recommended: npm install -g socket  (then 'socket npm install <pkg>' instead of plain npm install). Optional: 7-day age wrapper in ~/.zshrc." "supply.scanner"
  fi

  # .npmrc audit
  if [[ -f "$HOME/.npmrc" ]]; then
    if grep -qE "^[^#]*always-auth\s*=\s*false" "$HOME/.npmrc"; then
      warn ".npmrc has always-auth=false" "Audit your registry config" "supply.npmrc.alwaysauth"
    fi
    if grep -qE "^[^#]*registry\s*=\s*http://" "$HOME/.npmrc"; then
      fail ".npmrc points at an HTTP (not HTTPS) registry" "Switch to https://" "supply.npmrc.registry"
    fi
    # Inform about a `before=` cooldown if present
    if grep -qE "^[^#]*before\s*=" "$HOME/.npmrc"; then
      BEFORE_VAL=$(grep -E "^[^#]*before\s*=" "$HOME/.npmrc" | head -1 | sed 's/.*= *//')
      pass "npm cooldown active: before=${BEFORE_VAL} (.npmrc)" "supply.npmrc.cooldown"
    fi
  fi

  # gh CLI auth status
  if command -v gh >/dev/null 2>&1; then
    if $NETWORK; then
      GH_OUT=$(gh auth status 2>&1 || true)
      if echo "$GH_OUT" | grep -qiE "logged in to github\.com|active account: true"; then
        pass "gh CLI: logged in to GitHub" "supply.gh.auth"
      else
        skip "gh CLI installed but no active GitHub account" "Run: gh auth login" "supply.gh.auth"
      fi
    else
      skip "gh CLI auth status not checked (offline mode)" "Pass --network to let gh verify authentication status." "supply.gh.auth"
    fi
  fi

  # Git credential helper — `store` writes plaintext to ~/.git-credentials.
  if command -v git >/dev/null 2>&1; then
    GIT_HELPER=$(git config --global credential.helper 2>/dev/null || echo "")
    case "$GIT_HELPER" in
    store)
      fail "Git credential helper is 'store' (plaintext on disk)" "Switch: git config --global credential.helper osxkeychain (built-in) or use 1Password CLI / git-credential-manager." "supply.git.credentialhelper"
      ;;
    cache | "cache "*)
      warn "Git credential helper is 'cache' (in-memory, but unrestricted)" "Prefer osxkeychain or git-credential-manager." "supply.git.credentialhelper"
      ;;
    "")
      # No credential.helper is the right answer when the user has gone
      # SSH-only on purpose. We detect that via two signals together:
      #   (a) a url.<sshtarget>.insteadOf rewrite forces clones onto SSH
      #   (b) the SSH target is a known forge (github, gitlab, etc.)
      # If both, this row is a PASS — no HTTPS auth helper needed. Otherwise
      # fall back to the original "consider osxkeychain" SKIP.
      ssh_only=false
      _instead=$(git config --global --get-regexp 'url\..*\.insteadof' 2>/dev/null || echo "")
      while IFS= read -r line; do
        case "$line" in
        *"git@github.com:"* | *"git@gitlab.com:"* | *"git@bitbucket.org:"* | \
          *"ssh://git@github.com/"* | *"ssh://git@gitlab.com/"* | *"ssh://git@bitbucket.org/"* | \
          *"ssh://git@ssh.dev.azure.com/"* | *"git@codeberg.org:"* | *"git@gitea.com:"*)
          ssh_only=true
          break
          ;;
        esac
      done <<<"$_instead"
      if $ssh_only; then
        pass "Git credential helper not needed (SSH-only via insteadOf rewrite to trusted forge)" "supply.git.credentialhelper"
      else
        skip "Git credential helper not configured" "Optional: git config --global credential.helper osxkeychain — or go SSH-only by setting url.git@<forge>:.insteadOf https://<forge>/ and pointing remotes at git@" "supply.git.credentialhelper"
      fi
      ;;
    *osxkeychain* | *manager* | *1password* | *libsecret*)
      pass "Git credential helper: $GIT_HELPER" "supply.git.credentialhelper"
      ;;
    *)
      skip "Git credential helper: $GIT_HELPER" "Verify it's not writing tokens in plaintext to disk." "supply.git.credentialhelper"
      ;;
    esac

    # Global url.<base>.insteadOf rewrites. Most rewrites are MITM-shaped, but
    # the canonical SSH-to-forge form (e.g. `https://github.com/` →
    # `git@github.com:`) is a security IMPROVEMENT — the rewrite forces the
    # client off plaintext-token HTTPS onto SSH-key auth via the agent. Only
    # warn on rewrites whose target is NOT a well-known SSH forge endpoint.
    INSTEAD_OF=$(git config --global --get-regexp 'url\..*\.insteadof' 2>/dev/null || echo "")
    if [[ -n "$INSTEAD_OF" ]]; then
      INSTEAD_TRUSTED=0
      INSTEAD_OTHER=0
      INSTEAD_OTHER_KEYS=""
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Each line: "url.<TARGET>.insteadof <ORIGINAL>"
        key="${line%% *}"
        target="${key#url.}"
        target="${target%.insteadof}"
        case "$target" in
        "git@github.com:" | "git@gitlab.com:" | "git@bitbucket.org:" | \
          "ssh://git@github.com/" | "ssh://git@gitlab.com/" | "ssh://git@bitbucket.org/" | \
          "ssh://git@ssh.dev.azure.com/" | "git@codeberg.org:" | "git@gitea.com:")
          INSTEAD_TRUSTED=$((INSTEAD_TRUSTED + 1))
          ;;
        *)
          INSTEAD_OTHER=$((INSTEAD_OTHER + 1))
          INSTEAD_OTHER_KEYS+="$target; "
          ;;
        esac
      done <<<"$INSTEAD_OF"
      if [[ "$INSTEAD_OTHER" -eq 0 ]]; then
        pass "$INSTEAD_TRUSTED git url.<base>.insteadOf rewrite(s), all targeting trusted SSH forges" "supply.git.insteadof"
      else
        warn "$INSTEAD_OTHER non-SSH-forge git url.<base>.insteadOf rewrite(s): ${INSTEAD_OTHER_KEYS%; }" "Inspect: git config --global --get-regexp 'url\\..*\\.insteadof'. Rewrites to anything other than github/gitlab/bitbucket SSH endpoints can MITM clones." "supply.git.insteadof"
      fi
    else
      pass "No global git url.insteadOf rewrites" "supply.git.insteadof"
    fi

    # Global core.hooksPath — every repo on this machine then runs from one
    # location. Useful, but also one-stop persistence for an attacker.
    HOOKS_PATH=$(git config --global core.hooksPath 2>/dev/null || echo "")
    if [[ -n "$HOOKS_PATH" ]]; then
      warn "Global git core.hooksPath set: $(redact path "$HOOKS_PATH")" "Every repo runs hooks from there. Audit the directory contents." "supply.git.hookspath"
    else
      pass "No global git core.hooksPath override" "supply.git.hookspath"
    fi
  fi

  # Cargo / pip / gem credentials — same shape as the AWS/netrc/npmrc
  # checks in §14 (perm-and-presence), kept here because they belong to
  # package-manager supply chain.
  for spec in \
    "$HOME/.cargo/credentials.toml|supply.cargo.creds|cargo" \
    "$HOME/.cargo/credentials|supply.cargo.creds|cargo" \
    "$HOME/.pypirc|supply.pypirc.creds|pypirc" \
    "$HOME/.gem/credentials|supply.gem.creds|gem"; do
    cred_path="${spec%%|*}"
    rest="${spec#*|}"
    cred_id="${rest%%|*}"
    cred_name="${rest#*|}"
    [[ -f "$cred_path" ]] || continue
    PERMS=$(stat -f "%Lp" "$cred_path" 2>/dev/null || echo "?")
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
      warn "$cred_name credentials at $(redact path "$cred_path") (perms: $PERMS — tight, but plaintext on disk)" "Rotate periodically; prefer environment-injected tokens or platform keychains." "$cred_id"
    else
      fail "$cred_name credentials at $(redact path "$cred_path") with loose perms ($PERMS)" "chmod 600 $cred_path immediately and rotate the token." "$cred_id"
    fi
  done

  # Homebrew taps and analytics. Non-`homebrew/*` taps execute formula code
  # from third-party repos on every brew install — worth surfacing. Modern
  # Homebrew (>=4.0) doesn't list homebrew/core in `brew tap` output by
  # default (it ships via the Brew API), so an empty result is the
  # cleanest state and still deserves a PASS row.
  if command -v brew >/dev/null 2>&1; then
    BREW_TAPS=$(brew tap 2>/dev/null || true)
    THIRDPARTY_TAPS=""
    if [[ -n "$BREW_TAPS" ]]; then
      THIRDPARTY_TAPS=$(echo "$BREW_TAPS" | grep -vE '^(homebrew/|$)' | paste -sd, -)
    fi
    if [[ -n "$THIRDPARTY_TAPS" ]]; then
      if [[ "$REDACT" == "true" ]]; then
        TAP_COUNT=$( (printf '%s' "$THIRDPARTY_TAPS" | tr ',' '\n' | grep -c '.') || true)
        TAP_COUNT=${TAP_COUNT:-0}
        skip "${TAP_COUNT} third-party Homebrew tap(s) installed" "Each tap can ship formulae that run arbitrary code on install. Trust the tap maintainer." "supply.brew.taps"
      else
        skip "Third-party Homebrew taps: $THIRDPARTY_TAPS" "Each tap can ship formulae that run arbitrary code on install. Trust the tap maintainer." "supply.brew.taps"
      fi
    else
      pass "No third-party Homebrew taps installed" "supply.brew.taps"
    fi
    BREW_ANALYTICS=$(brew analytics 2>/dev/null | tr -d '\r' | head -1 || echo "")
    if echo "$BREW_ANALYTICS" | grep -qi "disabled"; then
      pass "Homebrew analytics disabled" "supply.brew.analytics"
    elif echo "$BREW_ANALYTICS" | grep -qi "enabled"; then
      skip "Homebrew analytics enabled" "Optional: brew analytics off (sends anonymized usage to Homebrew)." "supply.brew.analytics"
    fi
  fi

  _check_supply_direnv
  _check_supply_pip_extra_index
  _check_supply_uv_config

  # Composite: package-manager supply-chain posture.
  # The biggest single class of supply-chain attack against macOS devs is
  # a malicious postinstall script in npm/yarn/pnpm. ignore-scripts off +
  # no scanner = one bad `npm install` from a compromise. Surface the
  # combination as a posture verdict so the user sees it as one finding,
  # not three independent rows.
  # Accept warn|fail for the constituent rows: under --profile=web3 / paranoid
  # / developer, supply.{npm,yarn,pnpm}.ignorescripts and supply.scanner are
  # rewritten warn → fail by _apply_profile. Reading `== "warn"` only would
  # collapse to "scripts_open=0 / scanner=fail" → the composite's `else pass`
  # branch, silently exonerating the exact gaps the profile escalated.
  npm_warn=0
  pnpm_warn=0
  yarn_warn=0
  case "$(_status_of supply.npm.ignorescripts)" in warn | fail) npm_warn=1 ;; esac
  case "$(_status_of supply.pnpm.ignorescripts)" in warn | fail) pnpm_warn=1 ;; esac
  case "$(_status_of supply.yarn.ignorescripts)" in warn | fail) yarn_warn=1 ;; esac
  scripts_open=$((npm_warn + pnpm_warn + yarn_warn))
  scanner_state=$(_status_of supply.scanner)
  scanner_open=false
  case "$scanner_state" in warn | fail) scanner_open=true ;; esac
  if [[ "$scripts_open" -eq 0 && "$scanner_state" == "pass" ]]; then
    pass "Supply-chain posture: scripts disabled by default and a scanner is in place" "supply.posture"
  elif [[ "$scripts_open" -ge 2 ]] && $scanner_open; then
    fail "Supply-chain posture: $scripts_open package manager(s) run scripts on install AND no scanner present" "Critical exposure to a malicious postinstall. Set ignore-scripts=true on each manager and install Socket CLI; consider a 7-day cooldown wrapper too." "supply.posture"
  elif [[ "$scripts_open" -ge 1 ]] || $scanner_open; then
    warn "Supply-chain posture: gaps in package-manager hygiene" "Address the supply.* warns above as a set — partial coverage leaves the same hole." "supply.posture"
  else
    pass "Supply-chain posture: acceptable" "supply.posture"
  fi

}

section_14_credentials() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 14 · Credential & Secret Hygiene
  # ═════════════════════════════════════════════════════════════════════════════
  # SAFETY MODEL FOR THIS SECTION:
  #  - We only print file PATHS and pattern NAMES, never the matched values.
  #  - We use `grep -l` (filenames-only) and `grep -c` (counts), never content mode.
  #  - The OUTPUT of this section is itself sensitive — anyone seeing it learns
  #    where your credentials live. Redact paths before sharing.
  section "14 · Credential & Secret Hygiene"

  # Files that commonly leak credentials when developers paste tokens into them.
  SHELL_RCS=(
    "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshenv"
    "$HOME/.profile" "$HOME/.envrc" "$HOME/.env"
  )

  # High-confidence credential signatures. Each pattern is specific enough to avoid
  # matching ordinary text. Names only — we do NOT print the matched values.
  # Format: "label|regex"
  CRED_PATTERNS=(
    # Cloud / infra
    "AWS Access Key ID|AKIA[0-9A-Z]{16}"
    "AWS Temp Access Key|ASIA[0-9A-Z]{16}"
    "DigitalOcean PAT|dop_v1_[a-f0-9]{64}"
    "Google API Key|AIza[A-Za-z0-9_-]{35}"

    # Source / package registries
    "GitHub Personal Access Token|gh[pousr]_[A-Za-z0-9]{36,}"
    "GitHub Fine-grained PAT|github_pat_[A-Za-z0-9_]{82}"
    "GitLab Personal Access Token|glpat-[A-Za-z0-9_-]{20}"
    "npm Access Token|npm_[A-Za-z0-9]{36}"

    # AI / ML
    "OpenAI API Key|sk-(proj-)?[A-Za-z0-9_-]{20,}"
    "Anthropic API Key|sk-ant-[A-Za-z0-9_-]{20,}"
    "HuggingFace User Access Token|hf_[A-Za-z0-9]{30,}"
    "Replicate API Token|r8_[A-Za-z0-9]{30,}"

    # Payments / messaging / observability
    "Stripe Live Secret|sk_live_[A-Za-z0-9]{24,}"
    "Stripe Live Publishable|pk_live_[A-Za-z0-9]{24,}"
    "Slack Bot Token|xox[baprs]-[A-Za-z0-9-]{10,}"
    "Twilio API Key|SK[a-f0-9]{32}"
    "Sendgrid API Key|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
    "Mailgun API Key|key-[a-f0-9]{32}"
    "Sentry DSN|https://[a-f0-9]{32}@[a-z0-9.-]+/[0-9]+"
    "PostHog Personal API Key|phc_[A-Za-z0-9]{40,}"

    # Bots / chat platforms
    "Telegram Bot Token|[0-9]{8,12}:[A-Za-z0-9_-]{35}"
    "Discord Bot Token|[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}"
    "Discord MFA Token|mfa\.[A-Za-z0-9_-]{80,}"

    # Productivity SaaS
    "Notion Internal Integration Secret|secret_[A-Za-z0-9]{40,}"
    "Linear Personal API Key|lin_api_[A-Za-z0-9]{30,}"

    # Web3 / RPC URLs that EMBED the secret in the URL itself
    "Alchemy RPC URL with key|https://[a-z0-9-]+\.g\.alchemy\.com/v2/[A-Za-z0-9_-]{20,}"
    "Infura RPC URL with project ID|https://[a-z0-9-]+\.infura\.io/v3/[a-f0-9]{32}"
    "QuickNode RPC URL with token|https://[a-z0-9-]+\.quiknode\.pro/[a-f0-9]{32,}"

    # Catch-alls
    # "Vercel Token|^[a-zA-Z0-9]{24}$" — removed: pattern was too broad (any 24-char alnum line matched)
    "Generic JWT|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."
  )

  CREDS_FOUND_FILES=()
  for f in "${SHELL_RCS[@]}"; do
    [[ -f "$f" ]] || continue
    for entry in "${CRED_PATTERNS[@]}"; do
      label="${entry%%|*}"
      pattern="${entry#*|}"
      # -l = filename only, no matched content printed
      if grep -lE "$pattern" "$f" 2>/dev/null >/dev/null; then
        if ! _arr_contains "$f ($label)" ${CREDS_FOUND_FILES[@]+"${CREDS_FOUND_FILES[@]}"}; then
          CREDS_FOUND_FILES+=("$f ($label)")
        fi
      fi
    done
  done

  if [[ ${#CREDS_FOUND_FILES[@]} -gt 0 ]]; then
    fail "Plaintext credential pattern(s) in shell rc files: ${#CREDS_FOUND_FILES[@]}" "Move to 1Password or a secret manager. NEVER 'export FOO=secret' in your shell rc — those values end up in process env, child processes, terminal history, and crash dumps." "cred.shellrc.patterns"
    if [[ "$MODE" != "json" ]]; then
      for hit in "${CREDS_FOUND_FILES[@]}"; do
        printf "          %s· %s%s\n" "$DIM" "$(redact path "$hit")" "$NC"
      done
    fi
  else
    pass "No high-confidence credential patterns in shell rc files" "cred.shellrc.patterns"
  fi

  # Project-style credential files in $HOME root (a strong red flag — these belong in repos, not home dir)
  HOME_CRED_FILES=()
  for f in "$HOME/.env" "$HOME/.envrc" "$HOME/credentials.json" "$HOME/secrets.yml" "$HOME/secrets.yaml" "$HOME/private_key.txt" "$HOME/private.pem" "$HOME/api_key.txt"; do
    [[ -f "$f" ]] && HOME_CRED_FILES+=("$(basename "$f")")
  done
  if [[ ${#HOME_CRED_FILES[@]} -gt 0 ]]; then
    fail "Project-style credential files at \$HOME root: ${HOME_CRED_FILES[*]}" "Move into the project that needs them, or 1Password. Files at \$HOME root get backed up by everything (Time Machine, iCloud Drive if synced), and indexed by Spotlight." "cred.home.envfiles"
  else
    pass "No .env / credentials.json / private_key files at \$HOME root" "cred.home.envfiles"
  fi

  # AWS credentials file — exists is OK (standard tooling), but warn about plaintext
  if [[ -f "$HOME/.aws/credentials" ]]; then
    PERMS=$(stat -f "%Lp" "$HOME/.aws/credentials" 2>/dev/null || echo "?")
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
      warn "~/.aws/credentials exists with tight perms ($PERMS) — but secrets in plaintext on disk" "For better posture: aws-vault (encrypted at rest) or AWS SSO. https://github.com/99designs/aws-vault" "cred.aws.creds"
    else
      fail "~/.aws/credentials world-readable (perms: $PERMS)" "chmod 600 ~/.aws/credentials immediately. Then migrate to aws-vault." "cred.aws.creds"
    fi
  fi

  # .netrc — used for HTTP basic auth; if it has password lines, sensitive
  if [[ -f "$HOME/.netrc" ]]; then
    PERMS=$(stat -f "%Lp" "$HOME/.netrc" 2>/dev/null || echo "?")
    if grep -qE "^[[:space:]]*password" "$HOME/.netrc" 2>/dev/null; then
      if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
        warn "~/.netrc has password entries (perms: $PERMS — tight)" "Plaintext passwords on disk. Consider GitHub credential helpers / 1Password CLI / keychain instead." "cred.netrc.passwords"
      else
        fail "~/.netrc has password entries with loose perms ($PERMS)" "chmod 600 ~/.netrc immediately. Migrate to credential helper / 1Password." "cred.netrc.passwords"
      fi
    fi
  fi

  # .npmrc auth token (separate from earlier .npmrc audit which only checked registry)
  if [[ -f "$HOME/.npmrc" ]] && grep -qE "_authToken[[:space:]]*=" "$HOME/.npmrc" 2>/dev/null; then
    PERMS=$(stat -f "%Lp" "$HOME/.npmrc" 2>/dev/null || echo "?")
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
      warn "~/.npmrc has _authToken (perms: $PERMS — tight)" "Plaintext npm token. Rotate quarterly; consider 'npm login' over 'npm token create'." "cred.npmrc.token"
    else
      fail "~/.npmrc has _authToken with loose perms ($PERMS)" "chmod 600 ~/.npmrc and rotate the token (it may have been read by other processes)." "cred.npmrc.token"
    fi
  fi

  # Docker config — auth tokens often plaintext-base64 here
  if [[ -f "$HOME/.docker/config.json" ]] && grep -qE '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{8,}"' "$HOME/.docker/config.json" 2>/dev/null; then
    warn "~/.docker/config.json contains auth tokens" "These are base64 (not encrypted). Use 'docker logout' when not needed; consider 'docker-credential-osxkeychain' helper." "cred.docker.auth"
  fi

  # kubeconfig — bearer tokens / client cert keys
  KUBE="$HOME/.kube/config"
  if [[ -f "$KUBE" ]]; then
    PERMS=$(stat -f "%Lp" "$KUBE" 2>/dev/null || echo "?")
    if grep -qE "^[[:space:]]*(token|password):" "$KUBE" 2>/dev/null; then
      if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
        warn "~/.kube/config has plaintext token/password (perms: $PERMS)" "Consider using exec plugins or short-lived credentials instead of static tokens." "cred.kube.token"
      else
        fail "~/.kube/config has plaintext credentials with loose perms ($PERMS)" "chmod 600 ~/.kube/config and rotate." "cred.kube.token"
      fi
    fi
  fi

  # Git remote URLs containing embedded credentials (https://user:token@github.com/...)
  if [[ -f "$HOME/.gitconfig" ]] && grep -qE "https?://[^[:space:]/@]+:[^[:space:]/@]+@" "$HOME/.gitconfig" 2>/dev/null; then
    fail "~/.gitconfig has remote URL with embedded credentials" "Remove the embedded user:token from URLs. Use credential helper / SSH instead." "cred.gitconfig.embedded"
  fi

  # Hint about deeper scanning
  # Gitleaks: presence + nudge to actually run it. The §14 grep is a fast
  # triage; gitleaks does deeper pattern matching across the filesystem.
  if command -v gitleaks >/dev/null 2>&1; then
    GITLEAKS_VER=$(gitleaks version 2>/dev/null | head -1 | tr -d '\r' | awk '{print $NF}')
    pass "gitleaks installed${GITLEAKS_VER:+ (v${GITLEAKS_VER#v})} — periodically run: gitleaks detect --no-git -s \$HOME/Dev" "cred.gitleaks.hint"
  else
    skip "For a thorough sweep, run: 'brew install gitleaks && gitleaks detect --no-git -s ~/Dev'" "Gitleaks does deeper pattern matching across all files. The check above is a fast-path triage of the most common leak locations." "cred.gitleaks.hint"
  fi

}

section_15_password_2fa() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 15 · Password Manager & 2FA Hardware
  # ═════════════════════════════════════════════════════════════════════════════
  section "15 · Password Manager & 2FA Hardware"

  if pgrep -qi "1Password" 2>/dev/null; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Password manager is running" "pwmgr.running"
    else
      pass "1Password is running" "pwmgr.running"
    fi
  elif pgrep -qi "bitwarden" 2>/dev/null; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Password manager is running" "pwmgr.running"
    else
      pass "Bitwarden is running" "pwmgr.running"
    fi
  elif pgrep -qi "dashlane" 2>/dev/null; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Password manager is running" "pwmgr.running"
    else
      pass "Dashlane is running" "pwmgr.running"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      warn "No password manager process detected" "Use a reputable password manager for high-value secrets; macOS Keychain alone is a weaker posture." "pwmgr.running"
    else
      warn "No password manager process detected" "1Password / Bitwarden recommended; macOS Keychain alone is not enough for high-value secrets" "pwmgr.running"
    fi
  fi

  # FIDO2 / 2FA hardware-key tooling — distinct from crypto hardware wallets.
  HW_2FA_FOUND=()
  [[ -d "/Applications/YubiKey Manager.app" ]] && HW_2FA_FOUND+=("YubiKey Manager")
  [[ -d "/Applications/Yubico Authenticator.app" ]] && HW_2FA_FOUND+=("Yubico Authenticator")
  [[ -d "/Applications/OnlyKey.app" ]] && HW_2FA_FOUND+=("OnlyKey")
  [[ -d "/Applications/Nitrokey App.app" ]] && HW_2FA_FOUND+=("Nitrokey App")
  [[ -d "/Applications/Nitrokey App 2.app" ]] && HW_2FA_FOUND+=("Nitrokey App 2")
  # SoloKey (FIDO2 token) ships only as a CLI on macOS. There IS no
  # /Applications/Solo.app from the SoloKeys project, and that path collides
  # with a popular DAW — matching it produced false positives.
  command -v solo2 >/dev/null 2>&1 && HW_2FA_FOUND+=("solo2-cli")
  command -v solo >/dev/null 2>&1 && HW_2FA_FOUND+=("solo-cli")

  if [[ ${#HW_2FA_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "FIDO2 / 2FA hardware-key tooling detected (${#HW_2FA_FOUND[@]})" "twofa.hardware.installed"
    else
      pass "FIDO2 / 2FA hardware-key tooling: ${HW_2FA_FOUND[*]}" "twofa.hardware.installed"
    fi
  else
    if [[ -d "/Applications/Ledger Live.app" ]]; then
      if [[ "$REDACT" == "true" ]]; then
        skip "No dedicated FIDO2 hardware-key tooling — hardware wallet may cover this role" "Some hardware wallets can also act as a FIDO/U2F security key. Verify support in the vendor app, or use a dedicated hardware security key for cleaner UX." "twofa.hardware.installed"
      else
        skip "No dedicated FIDO2/YubiKey tooling — Ledger can cover this role" "Install the 'FIDO U2F' app on your Ledger (Ledger Live → My Ledger → Apps → FIDO U2F) to use it as a hardware key for account 2FA. Or buy a YubiKey for cleaner UX (Ledger = crypto signing; YubiKey = account 2FA)." "twofa.hardware.installed"
      fi
    else
      if [[ "$REDACT" == "true" ]]; then
        skip "No FIDO2 hardware-key tooling detected" "Recommended for high-value accounts. Crypto signing and account 2FA should generally use separate hardware roots." "twofa.hardware.installed"
      else
        skip "No FIDO2 hardware-key tooling detected" "Recommended for high-value accounts: YubiKey 5C NFC (~\$55). Use for 1Password, GitHub, Apple ID, Google, exchanges. Crypto wallets need a separate device (Ledger/Trezor)." "twofa.hardware.installed"
      fi
    fi
  fi

}

section_16_hardware_wallet() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 16 · Crypto Hardware Wallet
  # ═════════════════════════════════════════════════════════════════════════════
  section "16 · Crypto Hardware Wallet"

  HW_APPS=()
  [[ -d "/Applications/Ledger Live.app" ]] && HW_APPS+=("Ledger Live")
  [[ -d "/Applications/Trezor Suite.app" ]] && HW_APPS+=("Trezor Suite")
  [[ -d "/Applications/Keystone.app" ]] && HW_APPS+=("Keystone")
  [[ -d "/Applications/GridPlus Lattice1.app" ]] && HW_APPS+=("GridPlus Lattice1")
  if [[ ${#HW_APPS[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Hardware wallet app(s) installed (${#HW_APPS[@]})" "wallet.hw.installed"
    else
      pass "Hardware wallet app(s) installed: ${HW_APPS[*]}" "wallet.hw.installed"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "No hardware wallet app detected" "Strongly recommended for any non-trivial holdings." "wallet.hw.installed"
    else
      skip "No hardware wallet app detected" "Strongly recommended: Ledger or Trezor for any non-trivial holdings" "wallet.hw.installed"
    fi
  fi

  # Composite: FIDO2 hardware-key gap when a crypto hardware wallet is
  # already on hand. A Ledger ships a free "FIDO U2F" companion app that
  # turns the same device into a hardware key for account 2FA (1Password
  # / GitHub / Apple ID / exchanges). If the user has the wallet but no
  # dedicated FIDO key, point at the upgrade rather than recommending a
  # separate purchase.
  hw=$(_status_of "wallet.hw.installed")
  twofa=$(_status_of "twofa.hardware.installed")
  if [[ "$hw" == "pass" && "$twofa" != "pass" ]]; then
    if [[ "$REDACT" == "true" ]]; then
      skip "FIDO2 gap: hardware wallet present but no dedicated FIDO2 key" "Some hardware wallets can act as FIDO/U2F keys. Verify support in the vendor app, or add a dedicated hardware security key for account 2FA." "twofa.fido_gap"
    else
      skip "FIDO2 gap: hardware wallet present but no dedicated FIDO2 key" "Free upgrade: install the 'FIDO U2F' app on your Ledger (Ledger Live → My Ledger → Apps → FIDO U2F). Same device covers crypto signing AND account 2FA." "twofa.fido_gap"
    fi
  elif [[ "$hw" == "pass" && "$twofa" == "pass" ]]; then
    pass "FIDO2 + hardware wallet both available" "twofa.fido_gap"
  else
    skip "FIDO2 gap check not applicable (no hardware wallet)" "" "twofa.fido_gap"
  fi

}

section_17_folder_layout() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 17 · Folder Layout & Sensitive Data
  # ═════════════════════════════════════════════════════════════════════════════
  section "17 · Folder Layout & Sensitive Data"

  # Encrypted disk image / Vault sparsebundle
  VAULT_FOUND=()
  for path in \
    "$HOME/Vault.sparsebundle" "$HOME/Vault.dmg" \
    "$HOME/Documents/Vault.sparsebundle" "$HOME/Documents/Vault.dmg" \
    "$HOME/Desktop/Vault.sparsebundle" "$HOME/Desktop/Vault.dmg"; do
    [[ -e "$path" ]] && VAULT_FOUND+=("$path")
  done
  if [[ ${#VAULT_FOUND[@]} -gt 0 ]]; then
    pass "Encrypted Vault disk image found: $(redact path "${VAULT_FOUND[0]}")" "folder.vault.found"
  else
    skip "No encrypted Vault sparsebundle / dmg found at common paths" "Optional: create one for sensitive docs (Disk Utility → New Image → APFS Encrypted)" "folder.vault.found"
  fi

  # Downloads folder hygiene
  if [[ -d "$HOME/Downloads" ]]; then
    OLD_DL=$(find "$HOME/Downloads" -maxdepth 1 -mindepth 1 -mtime +30 2>/dev/null | wc -l | tr -d ' ')
    OLD_DL=${OLD_DL:-0}
    TOTAL_DL=$(find "$HOME/Downloads" -maxdepth 1 -mindepth 1 2>/dev/null | wc -l | tr -d ' ')
    TOTAL_DL=${TOTAL_DL:-0}
    if [[ "$OLD_DL" -eq 0 ]]; then
      pass "Downloads folder: $TOTAL_DL items, none older than 30 days" "folder.downloads.stale"
    elif [[ "$OLD_DL" -lt 50 ]]; then
      warn "Downloads folder: $OLD_DL items older than 30 days (of $TOTAL_DL total)" "Periodically clear old downloads" "folder.downloads.stale"
    else
      warn "Downloads folder: $OLD_DL items older than 30 days (of $TOTAL_DL total)" "Auto-clean recommended (Hazel rule or launchd job)" "folder.downloads.stale"
    fi
  fi

  # Sensitive folder names at $HOME root
  SENSITIVE_NAMES=("Finance" "Tax" "Taxes" "ID" "IDs" "Identity" "Crypto" "Wallet" "Passport")
  SENSITIVE_FOUND=()
  for name in "${SENSITIVE_NAMES[@]}"; do
    for d in "$HOME/$name" "$HOME/${name}_"*; do
      [[ -d "$d" ]] && SENSITIVE_FOUND+=("$(basename "$d")")
    done
  done
  if [[ ${#SENSITIVE_FOUND[@]} -gt 0 ]]; then
    warn "Sensitive folder names at \$HOME: ${SENSITIVE_FOUND[*]}" "Consider moving inside an encrypted Vault sparsebundle (mount on demand)" "folder.sensitive.names"
  fi

  # Cloud-sync exposure: SSH / cred dirs.
  # Uploading SSH private keys, AWS credentials, kubeconfig, or GPG to
  # iCloud Drive / Dropbox / etc. is recoverable by anyone with cloud-account
  # access — defeats FileVault, defeats key passphrases (the encrypted form
  # is still trivially brute-forceable offline). Hard fail by default; no
  # profile escalation needed.
  #
  # We resolve symlinks via `cd + pwd -P` (a subshell fork is acceptable here
  # — at most ~20 paths checked per run, only directories that exist) so the
  # check catches the common case where ~/.ssh is itself a symlink into
  # ~/Library/Mobile Documents/com~apple~CloudDocs/ (e.g., via the user's
  # "Desktop & Documents in iCloud Drive" setup).
  SSH_EXPOSURE_FOUND=()
  for d in "$HOME/.ssh" "$HOME/.aws" "$HOME/.kube" "$HOME/.gnupg"; do
    [[ -d "$d" ]] || continue
    real=$(cd "$d" 2>/dev/null && pwd -P)
    [[ -n "$real" ]] || continue
    provider=$(_path_in_cloud_root "$real")
    if [[ -n "$provider" ]]; then
      SSH_EXPOSURE_FOUND+=("$(basename "$d") → $provider")
    fi
  done
  if [[ ${#SSH_EXPOSURE_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      fail "${#SSH_EXPOSURE_FOUND[@]} SSH / credential dir(s) inside cloud sync" "Move these out of the synced folder immediately. SSH keys / AWS creds / kube tokens inside iCloud Drive / Dropbox / etc. are recoverable by anyone with cloud-account access — defeats FileVault at rest." "data.ssh.cloud_sync_exposure"
    else
      fail "SSH / credential dirs inside cloud sync: ${SSH_EXPOSURE_FOUND[*]}" "Move these out of the synced folder immediately. SSH keys / AWS creds / kube tokens inside iCloud Drive / Dropbox / etc. are recoverable by anyone with cloud-account access — defeats FileVault at rest." "data.ssh.cloud_sync_exposure"
    fi
  else
    pass "No SSH / credential dirs inside cloud sync" "data.ssh.cloud_sync_exposure"
  fi

  # Cloud-sync exposure: crypto wallet application data.
  # Wallet metadata, watch-only descriptors, and (for some wallets) encrypted
  # seed material lives in these dirs. Syncing them to a cloud provider is a
  # partial-key-exposure incident waiting to happen.
  CRYPTO_EXPOSURE_FOUND=()
  for d in \
    "$HOME/Library/Application Support/Ledger Live" \
    "$HOME/Library/Application Support/Trezor Suite" \
    "$HOME/Library/Ethereum" \
    "$HOME/.ethereum" \
    "$HOME/Library/Application Support/Electrum" \
    "$HOME/Library/Application Support/Sparrow" \
    "$HOME/Library/Application Support/Bitcoin"; do
    [[ -d "$d" ]] || continue
    real=$(cd "$d" 2>/dev/null && pwd -P)
    [[ -n "$real" ]] || continue
    provider=$(_path_in_cloud_root "$real")
    if [[ -n "$provider" ]]; then
      CRYPTO_EXPOSURE_FOUND+=("$(basename "$d") → $provider")
    fi
  done
  if [[ ${#CRYPTO_EXPOSURE_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "${#CRYPTO_EXPOSURE_FOUND[@]} wallet app data dir(s) inside cloud sync" "Wallet metadata + (for some wallets) encrypted seed material lives in these dirs. Move them out of cloud sync." "data.crypto.cloud_sync_exposure"
    else
      warn "Wallet app data inside cloud sync: ${CRYPTO_EXPOSURE_FOUND[*]}" "Wallet metadata + (for some wallets) encrypted seed material lives in these dirs. Move them out of cloud sync." "data.crypto.cloud_sync_exposure"
    fi
  else
    pass "No wallet app data inside cloud sync" "data.crypto.cloud_sync_exposure"
  fi

  # Cloud-sync exposure: shell / tooling dotfiles.
  # Complements Section 14's credential-pattern detection on the *location*
  # axis — even unscanned secret strings leak when these files are inside
  # a cloud-sync root. Files (not dirs); resolve parent dir to catch symlinks.
  DOTFILES_EXPOSURE_FOUND=()
  for f in \
    "$HOME/.gitconfig" \
    "$HOME/.zshrc" \
    "$HOME/.bashrc" \
    "$HOME/.zprofile" \
    "$HOME/.profile" \
    "$HOME/.netrc" \
    "$HOME/.pypirc" \
    "$HOME/.npmrc" \
    "$HOME/.cargo/credentials" \
    "$HOME/.gem/credentials"; do
    [[ -e "$f" ]] || continue
    parent=$(cd "$(dirname "$f")" 2>/dev/null && pwd -P)
    [[ -n "$parent" ]] || continue
    real="$parent/$(basename "$f")"
    provider=$(_path_in_cloud_root "$real")
    if [[ -n "$provider" ]]; then
      DOTFILES_EXPOSURE_FOUND+=("$(basename "$f") → $provider")
    fi
  done
  if [[ ${#DOTFILES_EXPOSURE_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "${#DOTFILES_EXPOSURE_FOUND[@]} dotfile(s) inside cloud sync" "Shell rc / npmrc / gitconfig etc. inside cloud sync exposes credentials and config to anyone with cloud-account access. Move them out." "data.dotfiles.cloud_sync_exposure"
    else
      warn "Dotfiles inside cloud sync: ${DOTFILES_EXPOSURE_FOUND[*]}" "Shell rc / npmrc / gitconfig etc. inside cloud sync exposes credentials and config to anyone with cloud-account access. Move them out." "data.dotfiles.cloud_sync_exposure"
    fi
  else
    pass "No tracked dotfiles inside cloud sync" "data.dotfiles.cloud_sync_exposure"
  fi

}

section_18_backups() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 18 · Backups (Time Machine + Offsite + Encryption Tools)
  # ═════════════════════════════════════════════════════════════════════════════
  section "18 · Backups (Time Machine + Offsite)"

  # Time Machine destinations
  TM_DEST=$(tmutil destinationinfo 2>&1 || true)
  if echo "$TM_DEST" | grep -qiE "no destinations|No backup destinations"; then
    warn "No Time Machine destinations configured" "System Settings → General → Time Machine → Add Backup Disk" "backup.tm.destination"
  elif echo "$TM_DEST" | grep -qi "Name *:"; then
    TM_NAME=$(echo "$TM_DEST" | grep -i "Name *:" | head -1 | sed 's/.*Name *: *//' | tr -d '\r')
    if [[ "$REDACT" == "true" ]]; then
      pass "Time Machine destination configured" "backup.tm.destination"
    else
      pass "Time Machine destination configured: ${TM_NAME:-(unnamed)}" "backup.tm.destination"
    fi
  else
    skip "Time Machine destination state could not be parsed" "" "backup.tm.destination"
  fi

  # Latest backup recency
  LAST_TM=$(tmutil latestbackup 2>&1 || true)
  if echo "$LAST_TM" | grep -qiE "/Backups\.backupdb|/com\.apple\.TimeMachine"; then
    LAST_DATE=$(echo "$LAST_TM" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}' | tail -1)
    if [[ -n "$LAST_DATE" ]]; then
      LAST_EPOCH=$(date -j -f "%Y-%m-%d-%H%M%S" "$LAST_DATE" +%s 2>/dev/null || echo "")
      NOW_EPOCH=$(date +%s)
      if [[ -n "$LAST_EPOCH" ]]; then
        AGE_DAYS=$(((NOW_EPOCH - LAST_EPOCH) / 86400))
        if [[ "$AGE_DAYS" -le 2 ]]; then
          pass "Time Machine: most recent backup ${AGE_DAYS} day(s) ago" "backup.tm.recency"
        elif [[ "$AGE_DAYS" -le 7 ]]; then
          warn "Time Machine: last backup ${AGE_DAYS} days ago" "Aim for at least weekly; daily preferred" "backup.tm.recency"
        else
          fail "Time Machine: last backup ${AGE_DAYS} days ago" "Plug in your TM drive and run a backup" "backup.tm.recency"
        fi
      else
        pass "Time Machine: backups present (date parse failed)" "backup.tm.recency"
      fi
    else
      pass "Time Machine: backups present" "backup.tm.recency"
    fi
  else
    skip "Time Machine: no recent backup found" "Run: tmutil latestbackup" "backup.tm.recency"
  fi

  # Auto-backup setting (informational)
  TM_AUTO=$(defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null || echo "")
  if [[ "$TM_AUTO" == "1" ]]; then
    pass "Time Machine auto-backup is on" "backup.tm.auto"
  elif [[ "$TM_AUTO" == "0" ]]; then
    warn "Time Machine auto-backup is off" "System Settings → General → Time Machine → Back up automatically" "backup.tm.auto"
  fi

  # Time Machine destination encryption.
  # tmutil destinationinfo emits an `Encrypted` field per destination on
  # Sonoma+ (and earlier for some configurations). Value is "1"/"0" or
  # "Yes"/"No" depending on macOS version. An unencrypted TM drive is a
  # full-disk image readable by anyone who steals it — defeats FileVault
  # at rest.
  #
  # Mixed-destinations handling: a user with two TM disks (one encrypted,
  # one not) needs to see the unencrypted one as a finding, not the
  # encrypted one as a pass. We count both states and let "any
  # unencrypted" dominate "any encrypted." Only emit pass when at least
  # one destination is explicitly encrypted AND none are explicitly
  # unencrypted.
  if echo "$TM_DEST" | grep -qiE "no destinations|No backup destinations"; then
    skip "Time Machine has no destination configured" "Once a destination is added, ensure 'Encrypt backup' is on." "backup.tm.encrypted"
  else
    TM_ENC_YES=$(echo "$TM_DEST" | grep -ciE "Encrypted *: *(1|Yes)" || true)
    TM_ENC_NO=$(echo "$TM_DEST" | grep -ciE "Encrypted *: *(0|No)" || true)
    TM_ENC_YES=${TM_ENC_YES:-0}
    TM_ENC_NO=${TM_ENC_NO:-0}
    if [[ "$TM_ENC_NO" -gt 0 ]]; then
      if [[ "$TM_ENC_YES" -gt 0 ]]; then
        warn "Time Machine: mixed destinations — $TM_ENC_NO unencrypted, $TM_ENC_YES encrypted" "An unencrypted TM disk is a full-disk image readable by anyone who steals it — defeats FileVault even though another destination is encrypted. System Settings → General → Time Machine → select the unencrypted disk → 'Encrypt Backup'." "backup.tm.encrypted"
      else
        warn "Time Machine destination is unencrypted" "An unencrypted TM drive is a full-disk image readable by anyone who steals it — defeats FileVault. System Settings → General → Time Machine → select disk → 'Encrypt Backup'." "backup.tm.encrypted"
      fi
    elif [[ "$TM_ENC_YES" -gt 0 ]]; then
      if [[ "$TM_ENC_YES" -gt 1 ]]; then
        pass "All $TM_ENC_YES Time Machine destinations are encrypted" "backup.tm.encrypted"
      else
        pass "Time Machine destination is encrypted" "backup.tm.encrypted"
      fi
    else
      skip "Time Machine encryption status not exposed by this tmutil version" "Verify manually: System Settings → General → Time Machine → backup disk → 'Encrypt backup' should be on." "backup.tm.encrypted"
    fi
  fi

  # Offsite backup tools
  BACKUP_FOUND=()
  [[ -d "/Applications/Backblaze.app" ]] && BACKUP_FOUND+=("Backblaze")
  [[ -d "/Applications/Carbon Copy Cloner.app" ]] && BACKUP_FOUND+=("Carbon Copy Cloner")
  [[ -d "/Applications/SuperDuper!.app" ]] && BACKUP_FOUND+=("SuperDuper!")
  [[ -d "/Applications/Arq.app" ]] || [[ -d "/Applications/Arq 7.app" ]] && BACKUP_FOUND+=("Arq")
  [[ -d "/Applications/Restic.app" ]] && BACKUP_FOUND+=("Restic")
  if [[ ${#BACKUP_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "Offsite/secondary backup tool(s) detected (${#BACKUP_FOUND[@]})" "backup.offsite"
    else
      pass "Offsite/secondary backup tool(s): ${BACKUP_FOUND[*]}" "backup.offsite"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      warn "No offsite backup tool detected" "Recommended: offsite encrypted backup with a private encryption key." "backup.offsite"
    else
      warn "No offsite backup tool detected" "Recommended: Backblaze with personal encryption key (offsite, encrypted)" "backup.offsite"
    fi
  fi

  # File-encryption tools
  ENC_FOUND=()
  [[ -d "/Applications/Cryptomator.app" ]] && ENC_FOUND+=("Cryptomator")
  [[ -d "/Applications/VeraCrypt.app" ]] && ENC_FOUND+=("VeraCrypt")
  [[ -d "/Applications/Encrypto.app" ]] && ENC_FOUND+=("Encrypto")
  if [[ ${#ENC_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      pass "File encryption tool(s) detected (${#ENC_FOUND[@]})" "backup.encryption"
    else
      pass "File encryption tool(s): ${ENC_FOUND[*]}" "backup.encryption"
    fi
  fi

  # Composite: backup recovery path.
  # Three classes of source matter here:
  #   STRONG: Time Machine (configured + not severely stale) and offsite
  #     tools (Backblaze, Arq, Carbon Copy Cloner, Restic). These cover
  #     the whole disk including dev environments, /Applications, system
  #     state, and offer versioning and ransomware resilience.
  #   PARTIAL: iCloud Drive sync. Covers documents + desktop (only if the
  #     user opted into "Desktop & Documents Folders"), Photos, and
  #     iCloud-aware app data. Does NOT cover /Applications, ~/Dev,
  #     brew installs, system config. Deletes propagate (no ransomware
  #     resilience), versioning ≤30d, and E2E encryption requires ADP.
  #     iCloud Backup (the iPhone feature) does not apply to Macs.
  # Inline detection because section_19_icloud runs after section_18_backups.
  tm_dest=$(_status_of "backup.tm.destination")
  tm_age=$(_status_of "backup.tm.recency")
  offsite=$(_status_of "backup.offsite")
  have_tm=false
  # Time Machine counts as a working source if a destination is configured;
  # a moderately stale recency is still a recovery path, just an old one.
  [[ "$tm_dest" == "pass" ]] && have_tm=true
  # Severely stale TM (>7 days = "fail") doesn't count as a working source
  # for the composite — by then the data on it is too old to recover from.
  [[ "$tm_age" == "fail" ]] && have_tm=false
  have_offsite=false
  [[ "$offsite" == "pass" ]] && have_offsite=true
  # iCloud Drive: presence of the local container directory is the
  # canonical signal that Drive is provisioned for this user.
  have_icloud=false
  [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]] && have_icloud=true

  if $have_tm && $have_offsite; then
    if $have_icloud; then
      pass "Backup recovery path: Time Machine + offsite + iCloud Drive — full coverage with redundancy" "backup.recovery_path"
    else
      pass "Backup recovery path: Time Machine + offsite — disk loss is recoverable" "backup.recovery_path"
    fi
  elif ($have_tm || $have_offsite) && $have_icloud; then
    primary=$($have_tm && echo "Time Machine" || echo "offsite")
    pass "Backup recovery path: $primary + iCloud Drive — full disk via $primary, documents redundant via iCloud" "backup.recovery_path"
  elif $have_tm || $have_offsite; then
    if [[ "$REDACT" == "true" ]]; then
      warn "Backup recovery path: single source — second source recommended" "Pair local full-disk backup with an offsite encrypted backup, or run two independent offsite backups." "backup.recovery_path"
    else
      warn "Backup recovery path: single source — second source recommended" "Either pair Time Machine with an offsite (Backblaze / Arq), or run two offsites. Both encrypted at rest." "backup.recovery_path"
    fi
  elif $have_icloud; then
    if [[ "$REDACT" == "true" ]]; then
      warn "Backup recovery path: cloud sync only — PARTIAL recovery (documents only)" "Cloud file sync does not cover applications, developer environments, package-manager state, or system state. Add local full-disk backup plus offsite encrypted backup for full coverage." "backup.recovery_path"
    else
      warn "Backup recovery path: iCloud Drive sync only — PARTIAL recovery (documents only)" "iCloud Drive syncs ~/Documents and ~/Desktop (only if you enabled 'Desktop & Documents Folders'), Photos, and iCloud-aware app data. It does NOT cover /Applications, ~/Dev, brew installs, or system state. Deletes propagate (no ransomware resilience), versioning ≤30d. Add a Time Machine drive + an offsite (Backblaze / Arq) for full coverage. Verify Advanced Data Protection is on at Settings → Apple ID for E2E encryption." "backup.recovery_path"
    fi
  else
    if [[ "$REDACT" == "true" ]]; then
      fail "Backup recovery path: NO source — disk loss is unrecoverable" "Configure local full-disk backup plus at least one encrypted offsite backup. Cloud file sync alone is not a backup." "backup.recovery_path"
    else
      fail "Backup recovery path: NO source — disk loss is unrecoverable" "Configure Time Machine + Backblaze (or equivalent). At least one offsite, encrypted at rest. Ransomware, drive failure, and accidental rm all assume you have a backup. iCloud Drive alone is not a backup — it's sync." "backup.recovery_path"
    fi
  fi

}

section_19_icloud() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 19 · iCloud & Drive Sync
  # ═════════════════════════════════════════════════════════════════════════════
  section "19 · iCloud & Drive Sync"

  # iCloud signed-in detection — multiple signals + better account-ID extraction.
  ICLOUD_SIGNALS=0
  ICLOUD_ACCT=""

  # Signal 1 + account-ID via plist file directly (more reliable than `defaults read`)
  MMA_PLIST="$HOME/Library/Preferences/MobileMeAccounts.plist"
  if [[ -f "$MMA_PLIST" ]]; then
    MMA_DUMP=$(plutil -p "$MMA_PLIST" 2>/dev/null || echo "")
    if echo "$MMA_DUMP" | grep -qi "AccountID"; then
      ICLOUD_SIGNALS=$((ICLOUD_SIGNALS + 1))
      # plutil format: "AccountID" => "user@example.com"
      ICLOUD_ACCT=$(echo "$MMA_DUMP" | awk -F'"' '/AccountID/ {print $4; exit}')
    fi
  fi

  # Signal 2: iCloud Drive container exists
  if [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]]; then
    ICLOUD_SIGNALS=$((ICLOUD_SIGNALS + 1))
  fi
  # Signal 3: cloudd / bird daemons
  if launchctl list 2>/dev/null | grep -qiE "com\.apple\.cloudd|com\.apple\.bird"; then
    ICLOUD_SIGNALS=$((ICLOUD_SIGNALS + 1))
  fi

  if [[ "$ICLOUD_SIGNALS" -ge 2 ]]; then
    if [[ -n "$ICLOUD_ACCT" ]]; then
      pass "iCloud signed in: $(redact email "$ICLOUD_ACCT")" "icloud.signedin"
    else
      pass "iCloud signed in (account ID unreadable)" "icloud.signedin"
    fi
  elif [[ "$ICLOUD_SIGNALS" -ge 1 ]]; then
    skip "iCloud may be signed in (one signal detected)" "Verify: Settings → Apple ID" "icloud.signedin"
  else
    skip "No iCloud account detected" "If signed in, multiple defaults reads were blocked — verify manually" "icloud.signedin"
  fi

  # Save-to-cloud default
  ICD=$(defaults read NSGlobalDomain NSDocumentSaveNewDocumentsToCloud 2>/dev/null || echo "")
  if [[ "$ICD" == "1" ]]; then
    warn "iCloud Drive saves new documents to cloud by default" "Trade-off: convenience vs. exposure. With ADP on, this is acceptable." "icloud.savetocloud"
  elif [[ "$ICD" == "0" ]]; then
    pass "New documents save locally by default (not iCloud)" "icloud.savetocloud"
  fi

  # iCloud Drive sync activity
  DD_CLOUD=$( (brctl status 2>/dev/null | grep -ci "iCloud Drive") || true)
  DD_CLOUD=${DD_CLOUD:-0}
  if [[ "$DD_CLOUD" -gt 0 ]]; then
    skip "iCloud Drive sync is active (verify ADP is on at Settings → Apple ID)" "" "icloud.drive.active"
  fi

  # Advanced Data Protection — not readable from CLI without private API
  skip "iCloud Advanced Data Protection (ADP) state" "Verify manually: Settings → Apple ID → iCloud → Advanced Data Protection should show 'On'" "icloud.adp"

  # "Desktop & Documents Folders" → iCloud Drive.
  # When enabled, ~/Desktop and ~/Documents are redirected into
  # ~/Library/Mobile Documents/com~apple~CloudDocs/. Anything saved there
  # (downloaded PDFs, screenshots, ad-hoc notes containing seed phrases,
  # transaction CSVs, the Vault.sparsebundle the user dragged to Desktop
  # "temporarily") is uploaded and replicated to every signed-in device.
  # On a wallet-holding Mac this is a major blast-radius expander.
  # Detection: the redirected folders exist as real directories under
  # the iCloud Drive root only when the feature is on.
  DDS_DESKTOP="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Desktop"
  DDS_DOCS="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Documents"
  if [[ -d "$DDS_DESKTOP" || -d "$DDS_DOCS" ]]; then
    DDS_WHICH=()
    [[ -d "$DDS_DESKTOP" ]] && DDS_WHICH+=("Desktop")
    [[ -d "$DDS_DOCS" ]] && DDS_WHICH+=("Documents")
    warn "iCloud 'Desktop & Documents Folders' sync is on (${DDS_WHICH[*]})" "Everything you drop on the Desktop or save to Documents is uploaded to iCloud and replicated to every other device signed in to your Apple ID. Without Advanced Data Protection, Apple holds the keys. Trade-off acceptable for low-sensitivity work; risky for wallet seeds, tax docs, key material. Disable: System Settings → Apple ID → iCloud → iCloud Drive → 'Desktop & Documents Folders' off." "cloud.icloud.desktop_documents_sync"
  else
    pass "iCloud Desktop & Documents Folders sync is off" "cloud.icloud.desktop_documents_sync"
  fi

}

section_20_users_sudo() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 20 · User Accounts & Sudo
  # ═════════════════════════════════════════════════════════════════════════════
  section "20 · User Accounts & Sudo"

  # Parse once, count from the parsed list. The previous code ran dscl twice
  # and used `wc -l` for the count — an empty parse silently became 0, which
  # then fell into the `-le 1` branch and emitted a hardcoded "1 admin user"
  # label with an empty list. Now: empty list → SKIP (not a false PASS);
  # non-empty list → actual count in the label. The `|| true` neutralises
  # `set -o pipefail` when grep -v filters out everything (legit empty case).
  ADMIN_LIST=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' '\n' | grep -v '^_' | grep -v '^root$' | grep -v '^$' | paste -sd, - || true)
  if [[ -z "$ADMIN_LIST" ]]; then
    # On some managed / newer macOS installs, dscl may omit GroupMembership
    # even though the admin group is queryable through directory services.
    # Fall back before giving up, but keep the no-false-PASS behavior.
    ADMIN_LIST=$(dscacheutil -q group -a name admin 2>/dev/null | awk -F': ' '/^users:/ {print $2; exit}' | tr ' ' '\n' | grep -v '^_' | grep -v '^root$' | grep -v '^$' | paste -sd, - || true)
  fi
  if [[ -z "$ADMIN_LIST" ]]; then
    skip "Admin group membership could not be parsed" "Verify manually: dscl . -read /Groups/admin GroupMembership" "user.admin.count"
  else
    ADMIN_USERS=$(printf '%s\n' "$ADMIN_LIST" | tr ',' '\n' | grep -c '.')
    if [[ "$ADMIN_USERS" -le 1 ]]; then
      pass "$ADMIN_USERS admin user: $(redact_list user "$ADMIN_LIST")" "user.admin.count"
    elif [[ "$ADMIN_USERS" -le 2 ]]; then
      pass "$ADMIN_USERS admin users: $(redact_list user "$ADMIN_LIST")" "user.admin.count"
    else
      warn "$ADMIN_USERS admin users: $(redact_list user "$ADMIN_LIST")" "Audit — least privilege means as few admins as possible" "user.admin.count"
    fi
  fi

  # Service accounts in admin group (red flag — they shouldn't be admin)
  SVC_IN_ADMIN=$(echo "$ADMIN_LIST" | tr ',' '\n' | grep -E "^(sys_|com\.|_)|\.nobody$|\.daemon$|\.helper$" | paste -sd, - || true)
  if [[ -n "$SVC_IN_ADMIN" ]]; then
    warn "Service accounts present in admin group: $(redact_list user "$SVC_IN_ADMIN")" "Demote with: sudo dseditgroup -o edit -d <user> -t user admin. Investigate which app installed them." "user.admin.svcaccts"
  fi

  # Total user accounts (informational) — exclude service accounts
  HUMAN_LIST=$(dscl . list /Users UniqueID 2>/dev/null |
    awk '$2 >= 501 && $1 !~ /^_/ && $1 !~ /^com\./ && $1 !~ /\.nobody$/ && $1 !~ /\.daemon$/ && $1 !~ /\.helper$/ && $1 !~ /^sys_/ {print $1}' |
    paste -sd, -)
  HUMAN_USERS=$( (echo "$HUMAN_LIST" | tr ',' '\n' | grep -c '^.\+$') || true)
  HUMAN_USERS=${HUMAN_USERS:-0}
  if [[ -n "$HUMAN_LIST" ]]; then
    if [[ "$HUMAN_USERS" -ge 2 ]]; then
      pass "Multiple user accounts ($HUMAN_USERS): $(redact_list user "$HUMAN_LIST") — supports vault-user separation" "user.human.count"
    else
      skip "Human user accounts: $HUMAN_USERS ($(redact_list user "$HUMAN_LIST"))" "Consider a separate macOS user for crypto / high-value work" "user.human.count"
    fi
  fi

  # NOPASSWD lines in sudoers (red flag)
  if ! $QUICK; then
    if sudo -n grep -rh "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -qv "^#"; then
      fail "Found NOPASSWD entries in sudoers" "Review: sudo grep -n NOPASSWD /etc/sudoers /etc/sudoers.d/*" "user.sudo.nopasswd"
    else
      pass "No NOPASSWD entries in sudoers" "user.sudo.nopasswd"
    fi
  fi

}

section_21_updates_findmy() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 21 · Software Updates & Find My Mac
  # ═════════════════════════════════════════════════════════════════════════════
  section "21 · Software Updates & Find My Mac"

  # Automatic background update checks.
  # `softwareupdate --schedule` is the canonical source; AutomaticCheckEnabled
  # is the underlying defaults key the GUI toggle writes. The previous
  # fallback accepted ANY of six unrelated keys at "1" as evidence that
  # checks were on — but AutomaticDownload only governs "download once a
  # check runs", CriticalUpdateInstall is a separate XProtect/MRT path,
  # AutomaticallyInstallMacOSUpdates is the "install OS updates" toggle, etc.
  # Each answers a different question; OR'ing them produced a near-tautology
  # that almost always returned PASS even on systems with auto-checks off.
  if softwareupdate --schedule 2>/dev/null | grep -qi "Automatic background checks: On"; then
    pass "Automatic update background checks are on" "update.auto"
  else
    ACE=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "")
    case "$ACE" in
    1) pass "Automatic update checks on (AutomaticCheckEnabled=1)" "update.auto" ;;
    0) warn "Automatic update checks are off (AutomaticCheckEnabled=0)" "System Settings → General → Software Update → Automatic Updates → Check for updates: On" "update.auto" ;;
    *) skip "Automatic update check state unreadable" "Verify: System Settings → General → Software Update → Automatic Updates" "update.auto" ;;
    esac
  fi

  # Find My Mac — multi-signal
  FM_SIGNALS=0
  defaults read MobileMeAccounts Accounts 2>/dev/null | grep -qi "FindMyMac" && FM_SIGNALS=$((FM_SIGNALS + 1))
  launchctl list 2>/dev/null | grep -qi "com.apple.findmymac\|com.apple.icloud.fmfd\|com.apple.icloud.searchpartyd" && FM_SIGNALS=$((FM_SIGNALS + 1))
  [[ -d "$HOME/Library/Application Support/com.apple.icloud.searchpartyd" ]] && FM_SIGNALS=$((FM_SIGNALS + 1))

  if [[ "$FM_SIGNALS" -ge 2 ]]; then
    pass "Find My Mac appears enabled (multiple signals)" "findmy.enabled"
  elif [[ "$FM_SIGNALS" -ge 1 ]]; then
    pass "Find My Mac likely enabled (one signal)" "findmy.enabled"
  else
    skip "Find My Mac state could not be confirmed" "Verify manually: Settings → Apple ID → Find My" "findmy.enabled"
  fi

  _check_update_macos_recency
}

_check_update_macos_recency() {
  # update.macos.recency — `update.auto` checks whether automatic update
  # checks are enabled, not whether the user has actually applied
  # updates. A common posture failure is "auto-update on, but every
  # update prompt gets 'Later'"; weeks pass and the OS is exposed to
  # patched vulnerabilities. We parse `softwareupdate --history` and
  # find the most recent install line that looks like a macOS / system
  # software update, then compute its age in days.
  #
  # Output format (from macOS 13+):
  #   Display Name                  Version    Date              Action
  #   ------------                  -------    ----              ------
  #   macOS Sonoma 14.5             14.5       05/18/2024, 11:23 Installed
  #   Safari Technology Preview     20.0       06/01/2024, 09:00 Installed
  #
  # We're looking for "macOS" or "Security Update" or "Safari" or
  # "Command Line Tools"; the first three indicate the user has
  # actually applied a system-level update.
  #
  # `softwareupdate` runs without sudo for --history. It does NOT touch
  # the network (the --no-scan flag is for paranoia; some macOS
  # versions check the catalog even with --history).
  if ! command -v softwareupdate >/dev/null 2>&1; then
    skip "softwareupdate not available; cannot check update recency" "" "update.macos.recency"
    return
  fi
  local SU_OUT
  SU_OUT=$(softwareupdate --history --no-scan 2>/dev/null || softwareupdate --history 2>/dev/null || true)
  if [[ -z "$SU_OUT" ]]; then
    skip "softwareupdate --history returned no rows" "Either no updates have ever been applied, or the history file is missing. Verify: softwareupdate --history" "update.macos.recency"
    return
  fi
  # Parse the most recent date column. Strategy: find any line that
  # looks like a system-relevant install, extract the MM/DD/YYYY
  # token, convert each to an epoch, take the max.
  local line max_epoch=0 date_token epoch
  while IFS= read -r line; do
    # Skip header + separator rows.
    case "$line" in
    "" | Display\ Name* | ----*) continue ;;
    esac
    # Filter to system-relevant rows. Anything else (Xcode CLI tools,
    # Migration Assistant, Pages, etc.) doesn't tell us about the OS.
    case "$line" in
    *macOS* | *Security\ Update* | *Safari* | *Rapid\ Security\ Response*) ;;
    *) continue ;;
    esac
    # Extract a MM/DD/YYYY token from the row.
    date_token=$(printf '%s' "$line" | grep -oE '[0-9]{2}/[0-9]{2}/[0-9]{4}' | head -1)
    [[ -n "$date_token" ]] || continue
    # `date -j -f` parses the literal date; macOS-specific syntax.
    epoch=$(date -j -f "%m/%d/%Y" "$date_token" +%s 2>/dev/null || true)
    [[ -n "$epoch" ]] || continue
    if [[ "$epoch" -gt "$max_epoch" ]]; then
      max_epoch="$epoch"
    fi
  done <<<"$SU_OUT"
  if [[ "$max_epoch" -eq 0 ]]; then
    skip "Could not parse a system update date from softwareupdate --history" "Format may have changed; consider opening an issue with 'softwareupdate --history | head' (no PII expected, but redact at will)." "update.macos.recency"
    return
  fi
  local now_epoch age_days
  now_epoch=$(date +%s)
  age_days=$(((now_epoch - max_epoch) / 86400))
  if [[ "$age_days" -le 45 ]]; then
    pass "Most recent macOS / Safari / Security update: $age_days day(s) ago" "update.macos.recency"
  elif [[ "$age_days" -le 90 ]]; then
    warn "Most recent macOS / Safari / Security update: $age_days days ago — apply pending updates" "Auto-update enabled is not the same as updates applied. Open System Settings → General → Software Update and install anything offered. Many CVEs ship in Safari + Security Update bundles between major macOS releases." "update.macos.recency"
  else
    warn "Most recent macOS / Safari / Security update: $age_days days ago — significantly behind" "More than 90 days since the last system-level update. Open System Settings → General → Software Update; the user-visible state ('No updates available') can lie when a deferral has been set. Check with: softwareupdate --list --no-scan." "update.macos.recency"
  fi
}

section_22_persistence_tcc() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 22 · Persistence & TCC
  # ═════════════════════════════════════════════════════════════════════════════
  # Surfaces autostart vectors and the privacy-database holders that an attacker
  # would target. All probes are strictly read-only:
  #   - filesystem listings (find on plist directories)
  #   - osascript invocations only use `to get name of every login item`
  #   - sqlite3 against TCC.db is invoked with -readonly
  # The tripwire allows osascript and sqlite3 only when those exact patterns
  # appear on the line.
  section "22 · Persistence & TCC"

  # User LaunchAgents — anything here starts at login under the user's identity.
  # When non-empty we list filenames inline (terminal mode only) so a reviewer
  # can spot unfamiliar agents without a second `ls` round-trip. JSON output
  # keeps the count only, and --redact suppresses inline listing so plist
  # names (which often embed bundle identifiers) can't leak into a shared
  # report.
  USER_LA_DIR="$HOME/Library/LaunchAgents"
  USER_LA_FILES=()
  if [[ -d "$USER_LA_DIR" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] && USER_LA_FILES+=("$f")
    done < <(find "$USER_LA_DIR" -maxdepth 1 -name '*.plist' 2>/dev/null | sort)
  fi
  USER_LA_COUNT=${#USER_LA_FILES[@]}
  if [[ "$USER_LA_COUNT" -eq 0 ]]; then
    pass "No user LaunchAgents in ~/Library/LaunchAgents/" "persist.user.launchagents"
  else
    warn "$USER_LA_COUNT user LaunchAgent(s) in ~/Library/LaunchAgents/" "Each *.plist starts a process at login. Investigate any you didn't install yourself." "persist.user.launchagents"
    if [[ "$MODE" != "json" && "$REDACT" != "true" ]]; then
      for f in "${USER_LA_FILES[@]}"; do
        printf "          %s· %s%s\n" "$DIM" "${f##*/}" "$NC"
      done
    fi
  fi

  # System LaunchAgents (every user) and LaunchDaemons (run as root).
  for kind_path in "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
    kind_name=$(echo "${kind_path##*/}" | tr '[:upper:]' '[:lower:]')
    kind_id="persist.system.${kind_name}"
    if [[ -d "$kind_path" ]]; then
      kind_count=$(find "$kind_path" -maxdepth 1 -name '*.plist' 2>/dev/null | wc -l | tr -d ' ')
      kind_count=${kind_count:-0}
      if [[ "$kind_count" -eq 0 ]]; then
        pass "$kind_path is empty" "$kind_id"
      else
        skip "$kind_count plist(s) in $kind_path" "Many are Apple-shipped. Compare to a baseline: ls -l $kind_path. Anything user-installed here runs at login (Agents) or as root (Daemons)." "$kind_id"
      fi
    fi
  done

  # Login items — read-only AppleScript (no `set`, no `do shell script`).
  # Automation of System Events requires the terminal to be granted Automation
  # permission. When that permission is missing osascript exits non-zero with
  # "Not authori[sz]ed to send Apple events" or error -1743. The previous
  # `2>/dev/null` made every Automation-denied terminal look like a PASS,
  # which is the worst possible failure mode for a persistence check. We now
  # merge stderr into stdout (2>&1) so we can detect the denial; on success
  # osascript writes only to stdout (comma-separated names), on denial only
  # to stderr — the streams don't overlap.
  LOGIN_RC=0
  LOGIN_OUT=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>&1) || LOGIN_RC=$?
  if [[ "$LOGIN_RC" -ne 0 ]]; then
    # Non-zero exit. Distinguish the canonical Automation-denied case
    # (so the user can grant the permission) from any other osascript
    # failure (so we don't misreport the error text as login-item names —
    # the original "elif -n $LOGIN_OUT" branch would have produced
    # output like "1 login item(s): execution error: ...").
    if grep -qiE "not authori[sz]ed|errOSACantAuth|-1743|access for assistive" <<<"$LOGIN_OUT"; then
      skip "Login items unreadable — terminal lacks Automation permission for System Events" "Grant: System Settings → Privacy & Security → Automation → enable this terminal → System Events." "persist.login_items"
    else
      skip "Login items unreadable — osascript exited $LOGIN_RC" "Audit manually: System Settings → General → Login Items." "persist.login_items"
    fi
  elif [[ -n "$LOGIN_OUT" ]]; then
    LOGIN_COUNT=$( (echo "$LOGIN_OUT" | tr ',' '\n' | grep -c '[^[:space:]]') || true)
    LOGIN_COUNT=${LOGIN_COUNT:-0}
    # Suppress the inline names under --json and --redact so app inventory
    # (which can identify the user) doesn't end up in a shared report.
    if [[ "$MODE" == "json" || "$REDACT" == "true" ]]; then
      skip "$LOGIN_COUNT login item(s) detected" "Audit: System Settings → General → Login Items. Anything unfamiliar is suspicious." "persist.login_items"
    else
      skip "$LOGIN_COUNT login item(s): $LOGIN_OUT" "Audit: System Settings → General → Login Items. Anything unfamiliar is suspicious." "persist.login_items"
    fi
  else
    pass "No login items detected" "persist.login_items"
  fi

  # User crontab — modern macOS uses launchd, so non-empty crontab is unusual.
  # When entries exist we surface them inline (terminal mode only) so the user
  # can decide what to keep without a second `crontab -l` round-trip. JSON
  # output keeps just the count to avoid embedding command lines that may
  # contain paths or tokens; --redact suppresses the inline listing for the
  # same reason.
  if command -v crontab >/dev/null 2>&1; then
    CRON_OUT=$(crontab -l 2>/dev/null || true)
    CRON_LINES=()
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
      CRON_LINES+=("$line")
    done <<<"$CRON_OUT"
    CRON_COUNT=${#CRON_LINES[@]}
    if [[ "$CRON_COUNT" -gt 0 ]]; then
      warn "$CRON_COUNT cron entries for current user" "Modern macOS uses launchd; cron entries are unusual. Investigate any you didn't add yourself — migrate to a LaunchAgent or remove with 'crontab -r'." "persist.cron"
      if [[ "$MODE" != "json" && "$REDACT" != "true" ]]; then
        for line in "${CRON_LINES[@]}"; do
          printf "          %s· %s%s\n" "$DIM" "$line" "$NC"
        done
      fi
    else
      pass "User crontab empty" "persist.cron"
    fi
  fi

  # TCC permission holders — only when sudo is available; the databases
  # themselves are TCC-protected, so the running terminal may need Full Disk
  # Access. Check BOTH user and system DBs; many sensitive approvals live in
  # the per-user DB. A partial read is SKIP, never a clean PASS.
  if $QUICK; then
    skip "TCC permission holders (requires sudo)" "" "tcc.holders"
    skip "TCC AppleEvents holders (requires sudo)" "" "tcc.appleevents"
    skip "TCC Camera + Microphone holders (requires sudo)" "" "tcc.camera_microphone"
  else
    if ! command -v sqlite3 >/dev/null 2>&1; then
      skip "TCC permission holders unreadable — sqlite3 not found" "" "tcc.holders"
      skip "TCC AppleEvents holders unreadable — sqlite3 not found" "" "tcc.appleevents"
      skip "TCC Camera + Microphone holders unreadable — sqlite3 not found" "" "tcc.camera_microphone"
    else
      TCC_OUT=""
      TCC_READABLE=0
      TCC_UNREADABLE=0
      TCC_UNREADABLE_LABELS=""
      for tcc_spec in \
        "user|$HOME/Library/Application Support/com.apple.TCC/TCC.db|false" \
        "system|/Library/Application Support/com.apple.TCC/TCC.db|true"; do
        tcc_scope="${tcc_spec%%|*}"
        rest="${tcc_spec#*|}"
        tcc_db="${rest%%|*}"
        tcc_sudo="${rest##*|}"

        if [[ "$tcc_sudo" == "true" ]]; then
          if sudo -n test -e "$tcc_db" 2>/dev/null; then
            tcc_exists=0
          else
            tcc_exists=1
          fi
        else
          if [[ -e "$tcc_db" ]]; then
            tcc_exists=0
          else
            tcc_exists=1
          fi
        fi
        if [[ "$tcc_exists" -ne 0 ]]; then
          TCC_UNREADABLE=$((TCC_UNREADABLE + 1))
          TCC_UNREADABLE_LABELS="${TCC_UNREADABLE_LABELS}${tcc_scope} "
          continue
        fi

        tcc_rc=0
        tcc_rows=$(_tcc_query_approved "$tcc_db" "$tcc_sudo") || tcc_rc=$?
        if [[ "$tcc_rc" -eq 0 ]]; then
          TCC_READABLE=$((TCC_READABLE + 1))
          while IFS= read -r tcc_row; do
            [[ -n "$tcc_row" ]] && TCC_OUT="${TCC_OUT}${TCC_OUT:+
}${tcc_scope}|${tcc_row}"
          done <<<"$tcc_rows"
        else
          TCC_UNREADABLE=$((TCC_UNREADABLE + 1))
          TCC_UNREADABLE_LABELS="${TCC_UNREADABLE_LABELS}${tcc_scope} "
        fi
      done

      if [[ "$TCC_READABLE" -eq 0 ]]; then
        skip "TCC databases not accessible (needs sudo + Full Disk Access for this terminal)" "Grant: System Settings → Privacy & Security → Full Disk Access → add your terminal" "tcc.holders"
        skip "TCC AppleEvents holders not readable" "" "tcc.appleevents"
        skip "TCC Camera + Microphone holders not readable" "" "tcc.camera_microphone"
      else
        TCC_COUNT=$( (printf '%s\n' "$TCC_OUT" | grep -c '.') || true)
        TCC_COUNT=${TCC_COUNT:-0}
        DANGEROUS_HOLDERS=""
        for svc in kTCCServiceAccessibility kTCCServiceListenEvent kTCCServiceScreenCapture kTCCServiceSystemPolicyAllFiles; do
          h=$(printf '%s\n' "$TCC_OUT" | awk -F'|' -v s="$svc" '$2 == s { print $1 ":" $3 }' | paste -sd, -)
          [[ -n "$h" ]] && DANGEROUS_HOLDERS+="${svc#kTCCService} → ${h}; "
        done
        if [[ -n "$DANGEROUS_HOLDERS" ]]; then
          if [[ "$REDACT" == "true" ]]; then
            SENSITIVE_SVC_COUNT=$( (printf '%s' "$DANGEROUS_HOLDERS" | tr ';' '\n' | grep -c '.') || true)
            SENSITIVE_SVC_COUNT=${SENSITIVE_SVC_COUNT:-0}
            skip "TCC: $TCC_COUNT permission grant(s); ${SENSITIVE_SVC_COUNT} sensitive service(s) have approved clients" "Verify: System Settings → Privacy & Security → Accessibility / Screen Recording / Full Disk Access / Input Monitoring." "tcc.holders"
          else
            skip "TCC: $TCC_COUNT permission grant(s). Sensitive: ${DANGEROUS_HOLDERS%; }" "Verify: System Settings → Privacy & Security → Accessibility / Screen Recording / Full Disk Access / Input Monitoring. Inspect any client you didn't approve." "tcc.holders"
          fi
        elif [[ "$TCC_UNREADABLE" -gt 0 ]]; then
          skip "TCC partial scan: $TCC_COUNT permission grant(s) in readable DB(s); unreadable scope(s): ${TCC_UNREADABLE_LABELS% }" "Grant Full Disk Access to this terminal and rerun before treating TCC as clean." "tcc.holders"
        else
          pass "$TCC_COUNT TCC grant(s); none in the most-sensitive list" "tcc.holders"
        fi

        # tcc.appleevents — AppleEvents grants are common (Zoom/Slack/IDE
        # automation) but worth surfacing because they enable cross-app
        # scripting; a compromised AppleEvents client can drive other
        # apps. Informational only, no profile escalation.
        AE_HOLDERS=$(printf '%s\n' "$TCC_OUT" | awk -F'|' -v s="kTCCServiceAppleEvents" '$2 == s { print $1 ":" $3 }' | paste -sd, -)
        AE_COUNT=$( (printf '%s\n' "$TCC_OUT" | awk -F'|' -v s="kTCCServiceAppleEvents" '$2 == s' | grep -c '.') || true)
        AE_COUNT=${AE_COUNT:-0}
        if [[ "$AE_COUNT" -eq 0 ]]; then
          pass "TCC AppleEvents: no approved clients" "tcc.appleevents"
        elif [[ "$REDACT" == "true" ]]; then
          skip "TCC AppleEvents: $AE_COUNT approved client(s)" "Each can drive other apps via Apple Events. Expected for Zoom / Slack / Raycast / IDE automation; review unfamiliar clients in System Settings → Privacy & Security → Automation." "tcc.appleevents"
        else
          skip "TCC AppleEvents: $AE_COUNT approved client(s) — ${AE_HOLDERS}" "Each can drive other apps via Apple Events. Expected for Zoom / Slack / Raycast / IDE automation; review unfamiliar clients in System Settings → Privacy & Security → Automation." "tcc.appleevents"
        fi

        # tcc.camera_microphone — combined count for Camera + Microphone.
        # Both common for video-conferencing apps and browsers; surface
        # as info only. Camera is the more sensitive of the two (visual
        # surveillance vs ambient audio); we list both grants but don't
        # escalate.
        CM_HOLDERS=""
        for svc in kTCCServiceCamera kTCCServiceMicrophone; do
          h=$(printf '%s\n' "$TCC_OUT" | awk -F'|' -v s="$svc" '$2 == s { print $1 ":" $3 }' | paste -sd, -)
          [[ -n "$h" ]] && CM_HOLDERS+="${svc#kTCCService} → ${h}; "
        done
        CM_COUNT=$( (printf '%s\n' "$TCC_OUT" | awk -F'|' '$2 == "kTCCServiceCamera" || $2 == "kTCCServiceMicrophone"' | grep -c '.') || true)
        CM_COUNT=${CM_COUNT:-0}
        if [[ "$CM_COUNT" -eq 0 ]]; then
          pass "TCC Camera + Microphone: no approved clients" "tcc.camera_microphone"
        elif [[ "$REDACT" == "true" ]]; then
          skip "TCC Camera + Microphone: $CM_COUNT approved client(s)" "Expected for video conferencing (Zoom / Webex / Teams) and browsers. Review unfamiliar clients in System Settings → Privacy & Security → Camera / Microphone." "tcc.camera_microphone"
        else
          skip "TCC Camera + Microphone: $CM_COUNT approved client(s) — ${CM_HOLDERS%; }" "Expected for video conferencing (Zoom / Webex / Teams) and browsers. Review unfamiliar clients in System Settings → Privacy & Security → Camera / Microphone." "tcc.camera_microphone"
        fi
      fi
    fi
  fi

  # Remote-access app presence.
  # AnyDesk, TeamViewer, et al. are the literal playbook for the "fake
  # interview" / ClickFake crypto-drainer pattern: attacker convinces target
  # to install AnyDesk for a "screen-share interview," grants Accessibility
  # + Screen Recording, drains wallets. Legitimate sysadmins do use these,
  # so default is `warn`; web3 and paranoid profiles escalate to `fail`
  # because there's no scenario where a wallet-holding Mac should also be
  # an inbound remote-control target.
  REMOTE_ACCESS_APPS=(
    "AnyDesk.app"
    "TeamViewer.app"
    "TeamViewerHost.app"
    "Splashtop Business.app"
    "Splashtop Streamer.app"
    "RustDesk.app"
    "Chrome Remote Desktop Host.app"
    "ChromeRemoteDesktopHost.app"
    "LogMeIn.app"
    "LogMeIn Client.app"
    "GoToMyPC.app"
    "ScreenConnect.app"
    "ConnectWiseControl.app"
    "RealVNC.app"
    "VNC Viewer.app"
    "Parsec.app"
  )
  # APP_ROOTS is overridable for tests so we can point at a sandbox $HOME
  # without depending on /Applications on the runner machine. In production
  # both paths are scanned.
  if [[ -z "${APP_ROOTS+set}" ]]; then
    APP_ROOTS=("/Applications" "$HOME/Applications")
  fi
  REMOTE_ACCESS_FOUND=()
  for app in "${REMOTE_ACCESS_APPS[@]}"; do
    for root in "${APP_ROOTS[@]}"; do
      if [[ -d "$root/$app" ]]; then
        REMOTE_ACCESS_FOUND+=("${app%.app}")
        break
      fi
    done
  done
  if [[ ${#REMOTE_ACCESS_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      warn "Remote-access app(s) installed: ${#REMOTE_ACCESS_FOUND[@]} found" "Remote-control tools (AnyDesk / TeamViewer / etc.) are central to crypto-drainer playbooks: attacker tricks user into installing one and granting Accessibility + Screen Recording. If you don't actively use these for sysadmin work, uninstall." "apps.remote_access.present"
    else
      warn "Remote-access app(s) installed: ${REMOTE_ACCESS_FOUND[*]}" "Remote-control tools (AnyDesk / TeamViewer / etc.) are central to crypto-drainer playbooks: attacker tricks user into installing one and granting Accessibility + Screen Recording. If you don't actively use these for sysadmin work, uninstall. Also revoke any stale TCC grants (System Settings → Privacy & Security → Accessibility / Screen Recording)." "apps.remote_access.present"
    fi
  else
    pass "No known remote-access apps installed" "apps.remote_access.present"
  fi

  # Sandbox runtime presence — informational nudge.
  # Having Docker / OrbStack / UTM available means the user has a ready
  # sandbox for "I want to try this random npm/pip/curl-pipe-bash but not
  # on my host." We don't penalise either state; absence gets a hint to
  # consider one, presence gets a pat-on-the-back without false confidence.
  SANDBOX_RUNTIMES=(
    "Docker.app"
    "OrbStack.app"
    "UTM.app"
    "Parallels Desktop.app"
    "VMware Fusion.app"
  )
  SANDBOX_FOUND=()
  for app in "${SANDBOX_RUNTIMES[@]}"; do
    for root in "${APP_ROOTS[@]}"; do
      if [[ -d "$root/$app" ]]; then
        SANDBOX_FOUND+=("${app%.app}")
        break
      fi
    done
  done
  # CLI-only runtimes — check $PATH lookups, not file globs. Overridable
  # for tests; empty array under tests yields the "no sandbox" path
  # deterministically.
  if [[ -z "${SANDBOX_CLI_BINS+set}" ]]; then
    SANDBOX_CLI_BINS=("lima" "colima")
  fi
  # bash 3.2 errors on empty-array @-expansion under set -u; the :+ guard
  # collapses to nothing when the array has zero elements.
  for bin in ${SANDBOX_CLI_BINS[@]+"${SANDBOX_CLI_BINS[@]}"}; do
    if command -v "$bin" >/dev/null 2>&1; then
      SANDBOX_FOUND+=("$bin")
    fi
  done
  if [[ ${#SANDBOX_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      skip "Sandbox runtime(s) available: ${#SANDBOX_FOUND[@]} found" "Use them for unfamiliar npm/pip packages, untrusted scripts, and pre-merge testing of dependencies. A container or VM is the cheapest blast-radius cut on macOS." "sandbox.runtime.present"
    else
      skip "Sandbox runtime(s) available: ${SANDBOX_FOUND[*]}" "Use them for unfamiliar npm/pip packages, untrusted scripts, and pre-merge testing of dependencies. A container or VM is the cheapest blast-radius cut on macOS." "sandbox.runtime.present"
    fi
  else
    skip "No sandbox runtime installed (Docker / OrbStack / UTM)" "Consider installing OrbStack (lightweight Docker alternative) or UTM (full VM) for testing untrusted packages without polluting the host." "sandbox.runtime.present"
  fi

  # gaming.client.installed — informational. Gaming clients aren't bad
  # on their own, but each one carries side effects worth surfacing on
  # a wallet-holding Mac:
  #   - Steam asks for Accessibility for its overlay → keystroke/UI
  #     introspection while Steam runs.
  #   - Discord is the dominant crypto-phishing channel: fake admin
  #     DMs, "verify your wallet" links, malicious bot invites.
  #     Account-takeover is also high-value because attackers can
  #     pivot to your contacts.
  #   - Epic / GOG / Battle.net are stored credentials + game-account
  #     value.
  # We don't penalise presence — just skip-with-advisory. The user can
  # decide whether the trade-off is worth it for their use.
  GAMING_CLIENTS=(
    "Steam.app"
    "Discord.app"
    "Epic Games Launcher.app"
    "GOG Galaxy.app"
    "Battle.net.app"
  )
  GAMING_FOUND=()
  for app in "${GAMING_CLIENTS[@]}"; do
    for root in "${APP_ROOTS[@]}"; do
      if [[ -d "$root/$app" ]]; then
        GAMING_FOUND+=("${app%.app}")
        break
      fi
    done
  done
  if [[ ${#GAMING_FOUND[@]} -eq 0 ]]; then
    pass "No gaming clients installed" "gaming.client.installed"
  else
    if [[ "$REDACT" == "true" ]]; then
      skip "${#GAMING_FOUND[@]} gaming client(s) installed" "Each gaming client is an attack surface worth reviewing on a wallet-holding Mac. Steam asks for Accessibility (UI introspection); Discord is the dominant crypto-phishing channel; the rest are stored-credential surfaces. Log out when unused; review TCC grants (System Settings → Privacy & Security → Accessibility / Screen Recording / Input Monitoring)." "gaming.client.installed"
    else
      skip "Gaming client(s) installed: ${GAMING_FOUND[*]}" "Each gaming client is an attack surface worth reviewing on a wallet-holding Mac. Steam asks for Accessibility (UI introspection); Discord is the dominant crypto-phishing channel (fake admin DMs, 'verify your wallet' links); the rest are stored-credential surfaces. Log out when unused; review TCC grants (System Settings → Privacy & Security → Accessibility / Screen Recording / Input Monitoring)." "gaming.client.installed"
    fi
  fi

  _check_persist_background_items
}

_check_persist_background_items() {
  # persist.background_items — Background Task Manager (sfltool dumpbtm)
  # is the modern equivalent of login items + LaunchAgents combined,
  # introduced in Ventura. It would be a great signal to count.
  #
  # The blocker: on macOS 13+, `sfltool dumpbtm` uses AuthorizationServices
  # to read /var/db/com.apple.backgroundtaskmanagement/, which triggers
  # a GUI authorization prompt ("sfltool wants to make changes"). That
  # prompt is NOT suppressed by `sudo -n` or any non-interactive flag —
  # the auth-framework hook runs before the binary even reads its argv.
  #
  # The audit's invariant is that default mode never pops modal prompts.
  # We therefore do NOT invoke sfltool. The check stays as an advisory
  # row pointing the user at the manual command. If we later find a
  # signal we CAN read non-interactively (e.g. the BTM plist file at a
  # path the user owns), we'll switch to that.
  if ! command -v sfltool >/dev/null 2>&1; then
    skip "sfltool not available (pre-Ventura macOS); skipping background items check" "" "persist.background_items"
    return
  fi
  skip "Background items not enumerable read-only (sfltool dumpbtm triggers a GUI authorization prompt)" "To inspect manually: 'sfltool dumpbtm | less' (you'll see a one-time auth prompt). Most entries are legitimate (Dropbox / 1Password / Slack / Mail extensions); remove unfamiliar ones via System Settings → General → Login Items." "persist.background_items"
}

section_23_device_mgmt_privacy() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 23 · Device Management & Privacy Awareness
  # ═════════════════════════════════════════════════════════════════════════════
  # Three small awareness checks that aren't binary security controls but
  # frequently surprise users:
  #   23.1  MDM enrollment status (especially relevant when joining/leaving
  #         a company; DEP-enrolled devices behave differently).
  #   23.2  Screenshot save location — leaks to iCloud / Dropbox / Google
  #         Drive if pointed at a synced folder.
  #   23.3  Clipboard manager presence — Maccy/Paste/Raycast/Alfred all keep
  #         history of every clipboard event, including pasted seed phrases,
  #         MFA codes, and 1Password autofills.
  section "23 · Device Management & Privacy Awareness"

  # MDM enrollment status. `profiles status -type enrollment` is read-only
  # and prints two lines: "Enrolled via DEP: Yes/No" and "MDM enrollment:
  # Yes/Yes (User Approved)/No". Privileged-only on some macOS versions.
  if $QUICK; then
    skip "MDM enrollment status (requires sudo)" "" "system.mdm.enrolled"
  else
    MDM_STATUS=$(sudo -n profiles status -type enrollment 2>/dev/null || profiles status -type enrollment 2>/dev/null || true)
    case "$MDM_STATUS" in
    *"MDM enrollment: Yes (User Approved)"*)
      skip "MDM-enrolled (User Approved). $(echo "$MDM_STATUS" | grep -i 'Enrolled via DEP' | head -1 | sed 's/^[[:space:]]*//')" "Inspect the managing org under System Settings → Privacy & Security → Profiles." "system.mdm.enrolled"
      ;;
    *"MDM enrollment: Yes"*)
      skip "MDM-enrolled. $(echo "$MDM_STATUS" | grep -i 'Enrolled via DEP' | head -1 | sed 's/^[[:space:]]*//')" "Inspect the managing org under System Settings → Privacy & Security → Profiles." "system.mdm.enrolled"
      ;;
    *"MDM enrollment: No"*)
      pass "Not MDM-enrolled" "system.mdm.enrolled"
      ;;
    *)
      skip "MDM enrollment status could not be queried" "Run: sudo profiles status -type enrollment" "system.mdm.enrolled"
      ;;
    esac
  fi

  # Screenshot save location. If pointed at iCloud Drive or another synced
  # folder, every Cmd-Shift-4 leaks to the cloud. Default is ~/Desktop.
  SCREENSHOT_LOC=$(defaults read com.apple.screencapture location 2>/dev/null || echo "")
  if [[ -z "$SCREENSHOT_LOC" ]]; then
    pass "Screenshots save to default ~/Desktop" "privacy.screenshot.location"
  else
    # Expand tilde + env vars so the comparison sees an absolute path.
    expanded="${SCREENSHOT_LOC/#\~/$HOME}"
    case "$expanded" in
    *"Library/Mobile Documents/com~apple~CloudDocs"* | *"iCloud"*)
      warn "Screenshots save to an iCloud-synced folder: $(redact path "$expanded")" "Every screenshot uploads to iCloud. Move to a local folder if you screenshot wallets / 2FA codes / private chats." "privacy.screenshot.location"
      ;;
    *Dropbox* | *"Google Drive"* | *OneDrive* | *Box*)
      warn "Screenshots save to a cloud-synced folder: $(redact path "$expanded")" "Every screenshot uploads to the third-party sync provider. Use a local folder for sensitive captures." "privacy.screenshot.location"
      ;;
    *)
      pass "Screenshots save to a local folder: $(redact path "$expanded")" "privacy.screenshot.location"
      ;;
    esac
  fi

  # Clipboard manager detection. These tools keep every clipboard event in
  # history — useful, but a high-value target for malware and an easy way
  # to leak pasted secrets long after the paste.
  CLIPBOARD_FOUND=()
  CLIP_TABLE=(
    "/Applications/Maccy.app|maccy|Maccy"
    # Avoid the bare "paste" pattern — it would match `pasted`, the macOS
    # PasteboardServer daemon at /usr/sbin/pasted. Match the bundle path
    # in the running binary's argv instead.
    "/Applications/Paste.app|Paste\.app/Contents|Paste"
    "/Applications/Raycast.app|Raycast|Raycast (clipboard history opt-in)"
    "/Applications/Alfred 5.app /Applications/Alfred 4.app /Applications/Alfred.app|Alfred|Alfred (clipboard history opt-in)"
    "/Applications/Pastebot.app|Pastebot|Pastebot"
    "/Applications/CopyClip.app /Applications/CopyClip 2.app|CopyClip|CopyClip"
    "/Applications/Pasta.app|pasta|Pasta"
  )
  for row in "${CLIP_TABLE[@]}"; do
    bundles="${row%%|*}"
    rest="${row#*|}"
    proc="${rest%%|*}"
    name="${rest##*|}"
    hit=false
    for b in $bundles; do
      [[ -d "$b" ]] && {
        hit=true
        break
      }
    done
    if ! $hit && _proc_running "$proc"; then
      hit=true
    fi
    if $hit && ! _arr_contains "$name" ${CLIPBOARD_FOUND[@]+"${CLIPBOARD_FOUND[@]}"}; then
      CLIPBOARD_FOUND+=("$name")
    fi
  done
  if [[ ${#CLIPBOARD_FOUND[@]} -gt 0 ]]; then
    if [[ "$REDACT" == "true" ]]; then
      skip "${#CLIPBOARD_FOUND[@]} clipboard manager(s) detected" "Each retains paste history. Audit retention settings; never paste seed phrases, recovery codes, or password-manager items into apps with clipboard history enabled." "privacy.clipboard.manager"
    else
      skip "Clipboard manager(s) detected: ${CLIPBOARD_FOUND[*]}" "Each retains paste history. Audit retention settings; never paste seed phrases, recovery codes, or 1Password vault items into apps with clipboard history enabled." "privacy.clipboard.manager"
    fi
  else
    pass "No clipboard-manager-with-history app detected" "privacy.clipboard.manager"
  fi

}

section_24_ide_trust() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 24 · IDE Workspace Trust + Wallet Isolation Composite
  # ═════════════════════════════════════════════════════════════════════════════
  # IDE workspace trust is the in-editor defence against the "open malicious
  # repo → tasks.json autoruns" attack pattern. VS Code shipped Workspace
  # Trust in 1.57; Cursor inherits it. When enabled (the default), opening
  # an untrusted folder disables task auto-run, language servers that opt
  # in, and extensions that opt in to restricted mode. When the user sets
  # security.workspace.trust.enabled=false they've reverted to the
  # pre-1.57 behaviour where every cloned repo can immediately execute code.
  #
  # We deliberately use grep, not a JSONC parser. VS Code's settings.json
  # is JSONC (JSON with comments + trailing commas), and shelling out to a
  # parser would be a portability headache for what is essentially a
  # string-match on three well-known keys. The trade-off: a setting buried
  # inside a comment, or split awkwardly across lines, can be missed. We
  # document this and prefer false negatives ("looks OK") over false
  # positives.
  section "24 · IDE Workspace Trust + Wallet Isolation"

  # IDE_APP_ROOTS is overridable so tests can scan a sandbox dir instead
  # of /Applications on the runner machine — otherwise installed VS Code
  # / Cursor on the developer's actual Mac contaminates "not detected"
  # baselines.
  if [[ -z "${IDE_APP_ROOTS+set}" ]]; then
    IDE_APP_ROOTS=("/Applications" "$HOME/Applications")
  fi

  # _check_ide_trust LABEL ID SETTINGS_FILE APP_BUNDLE
  # Emits exactly one row per IDE. Skip if no settings file and no app
  # bundle visible under IDE_APP_ROOTS. Otherwise grep the settings file
  # for the three known-bad workspace-trust opt-outs.
  _check_ide_trust() {
    local label="$1" id="$2" settings_file="$3" bundle="$4"
    local app_present=false app_root
    for app_root in ${IDE_APP_ROOTS[@]+"${IDE_APP_ROOTS[@]}"}; do
      if [[ -d "$app_root/$bundle" ]]; then
        app_present=true
        break
      fi
    done
    if [[ ! -f "$settings_file" && "$app_present" == "false" ]]; then
      skip "$label not detected (no settings file, no app bundle)" "" "$id"
      return
    fi
    if [[ ! -f "$settings_file" ]]; then
      # App installed but no user settings yet — defaults apply (trust on).
      pass "$label installed; no user settings override workspace trust defaults" "$id"
      return
    fi
    # Grep is fed the file directly so we don't read large files into bash.
    # The regex tolerates whitespace between key/colon/value to match the
    # most common formatting choices. JSONC comments are NOT stripped:
    # documented limitation in the section header.
    local issues=()
    if grep -qE '"security\.workspace\.trust\.enabled"[[:space:]]*:[[:space:]]*false' "$settings_file" 2>/dev/null; then
      issues+=("workspace trust DISABLED")
    fi
    if grep -qE '"security\.workspace\.trust\.untrustedFiles"[[:space:]]*:[[:space:]]*"open"' "$settings_file" 2>/dev/null; then
      issues+=("untrusted files auto-open")
    fi
    if grep -qE '"security\.workspace\.trust\.startupPrompt"[[:space:]]*:[[:space:]]*"never"' "$settings_file" 2>/dev/null; then
      issues+=("startup prompt suppressed")
    fi
    if [[ ${#issues[@]} -eq 0 ]]; then
      pass "$label: workspace trust at defaults (enabled)" "$id"
      return
    fi
    # Any disable → fail; the other two are warnings.
    local disabled=false issue
    for issue in "${issues[@]}"; do
      [[ "$issue" == "workspace trust DISABLED" ]] && disabled=true
    done
    local joined
    joined=$(printf '%s; ' "${issues[@]}")
    joined="${joined%; }"
    if [[ "$disabled" == "true" ]]; then
      fail "$label workspace trust posture: ${joined}" "Re-enable in Cmd-, → search 'workspace trust' → check 'Security: Workspace Trust Enabled'. Opening untrusted repos with trust off auto-runs tasks.json, scripts in language servers, and extension code." "$id"
    else
      warn "$label workspace trust posture: ${joined}" "Set 'security.workspace.trust.untrustedFiles' to 'prompt' (the default), and 'security.workspace.trust.startupPrompt' to 'always' or 'once'. Both protect against malicious-repo auto-run." "$id"
    fi
  }

  _check_ide_trust \
    "VS Code" \
    "ide.vscode.workspace_trust" \
    "$HOME/Library/Application Support/Code/User/settings.json" \
    "Visual Studio Code.app"

  _check_ide_trust \
    "Cursor" \
    "ide.cursor.workspace_trust" \
    "$HOME/Library/Application Support/Cursor/User/settings.json" \
    "Cursor.app"

  # users.crypto_isolation_indicator — cross-section composite.
  # Fires only when wallet extensions are present (ext.wallet has emitted
  # warn or fail; pass means no wallets, skip means N/A). Measures whether
  # the wallet workflow is isolated from everyday browsing surface:
  #   1. Multiple human user accounts (user.human.count = pass) — so the
  #      wallet user can be separate from the daily-driver user.
  #   2. Default browser is the recommended baseline (browser.default = pass
  #      or skip) — implying random-link browsing happens in a different
  #      browser from the one holding the wallet, OR the user has
  #      consciously chosen their browser.
  # We deliberately do NOT include the FIDO2 gap here — that's its own
  # twofa.fido_gap composite. Keeping the indicators tightly scoped.
  local wallet_state
  wallet_state=$(_status_of "ext.wallet")
  if [[ "$wallet_state" != "warn" && "$wallet_state" != "fail" ]]; then
    skip "Wallet isolation N/A (no wallet extensions detected)" "" "users.crypto_isolation_indicator"
  else
    local gaps=()
    local users_state browser_state
    users_state=$(_status_of "user.human.count")
    browser_state=$(_status_of "browser.default")
    if [[ "$users_state" != "pass" ]]; then
      gaps+=("single user account on this Mac")
    fi
    if [[ "$browser_state" == "warn" ]]; then
      gaps+=("default browser is the same risk surface as the wallet browser")
    fi
    if [[ ${#gaps[@]} -eq 0 ]]; then
      pass "Wallet workflow shows isolation indicators (multi-user + non-default-browser posture)" "users.crypto_isolation_indicator"
    else
      local joined
      joined=$(printf '%s + ' "${gaps[@]}")
      joined="${joined% + }"
      warn "Wallet isolation gaps: ${joined}" "Highest-leverage fix: dedicated macOS user account for wallet operations, accessed only when signing. Random-link browsing stays on the main account." "users.crypto_isolation_indicator"
    fi
  fi
}

section_25_messaging() {
  # ═════════════════════════════════════════════════════════════════════════════
  # 25 · Messaging Apps (advisory)
  # ═════════════════════════════════════════════════════════════════════════════
  # Messaging apps store their settings in opaque per-app stores (Telegram's
  # tdata is encrypted binary; Signal uses a SQLCipher database; Discord
  # uses an Electron leveldb). We can detect *presence* but not the actual
  # privacy settings the user cares about — auto-download of media,
  # group-add restrictions, link-preview behaviour.
  #
  # The right shape for these checks is therefore *advisory*: when the app
  # is installed, emit a skip with the explicit settings the user should
  # verify by hand. When the app is absent, emit pass. We deliberately do
  # NOT flag presence itself as a finding — Telegram (and the rest) are
  # legitimate tools; the risk is in default configurations.
  section "25 · Messaging Apps (advisory)"

  # Telegram Desktop.
  # Real-world targeting pattern: attacker DMs the target a "PDF" or
  # "image"; with auto-download on, the file lands in the user's
  # ~/Downloads silently, sometimes opening on hover-preview. Combined
  # with "anyone can add me to group chats" the attacker doesn't even
  # need to know the target's username — they can spray-add from a
  # bought list.
  # Initialise APP_ROOTS here in case section 25 runs in a context where
  # section 22's initialisation didn't (e.g. unit tests that drive
  # section_25_messaging directly).
  if [[ -z "${APP_ROOTS+set}" ]]; then
    APP_ROOTS=("/Applications" "$HOME/Applications")
  fi
  TELEGRAM_BUNDLES=(
    "Telegram.app"
    "Telegram Desktop.app"
    "Telegram Lite.app"
  )
  TELEGRAM_FOUND=()
  for app in "${TELEGRAM_BUNDLES[@]}"; do
    for root in "${APP_ROOTS[@]}"; do
      if [[ -d "$root/$app" ]]; then
        TELEGRAM_FOUND+=("${app%.app}")
        break
      fi
    done
  done
  if [[ ${#TELEGRAM_FOUND[@]} -gt 0 ]]; then
    skip "Telegram Desktop installed — verify privacy defaults manually" "tdata is encrypted, so this check can't read settings directly. Open Telegram → Settings → and verify: (a) Privacy → 'Who can add me to group chats?' is 'My Contacts' or 'Nobody'; (b) Advanced → Automatic Media Download is OFF for private chats, groups, and channels (especially while on mobile data and roaming); (c) Privacy → Messages → 'Read time' and 'Last Seen' restricted to contacts. Default-on auto-download is the most common targeting vector — attacker DMs a 'PDF' and it lands on disk silently." "messaging.telegram.advisory"
  else
    pass "Telegram Desktop not installed" "messaging.telegram.advisory"
  fi
}

run_all_sections() {
  section_01_system_integrity
  section_02_login_lock
  section_03_privacy_telemetry
  section_04_firewall_sharing
  section_05_airdrop_bluetooth
  section_06_dns_outbound
  section_07_filters_proxies
  section_08_av_endpoint
  section_09_browsers
  section_10_browser_extensions
  section_11_ssh
  section_12_git_signing
  section_13_supply_chain
  section_14_credentials
  section_15_password_2fa
  section_16_hardware_wallet
  section_17_folder_layout
  section_18_backups
  section_19_icloud
  section_20_users_sudo
  section_21_updates_findmy
  section_22_persistence_tcc
  section_23_device_mgmt_privacy
  section_24_ide_trust
  section_25_messaging
}

_diff_parse_rows() {
  # _diff_parse_rows SOURCE_NAME
  # Reads one mac-posture-audit JSON document from stdin and emits
  # "id status" lines. This is deliberately small and schema-specific so
  # --diff does not depend on python3/jq/node.
  local source="$1" compact rows split_rows obj id status seen idx
  compact=$(cat | tr '\n' ' ' | sed 's/[[:space:]]//g') || return 2
  if [[ "$compact" != *'"results":['* ]]; then
    printf -- '--diff: %s JSON must contain a results array\n' "$source" >&2
    return 2
  fi
  rows=$(printf '%s' "$compact" | sed -E 's/^.*"results":\[(.*)\]\}.*$/\1/')
  if [[ "$rows" == "$compact" ]]; then
    printf -- '--diff: %s JSON must contain a results array\n' "$source" >&2
    return 2
  fi
  [[ -z "$rows" ]] && return 0

  split_rows=$(printf '%s' "$rows" | sed 's/},{/}\
{/g')
  seen=" "
  idx=0
  while IFS= read -r obj; do
    [[ -z "$obj" ]] && continue
    id=$(printf '%s' "$obj" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    status=$(printf '%s' "$obj" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
    if [[ -z "$id" ]]; then
      printf -- '--diff: %s results[%d].id must be a non-empty string\n' "$source" "$idx" >&2
      return 2
    fi
    case "$status" in
    pass | warn | fail | skip) ;;
    *)
      printf -- '--diff: %s results[%d].status must be pass|warn|fail|skip\n' "$source" "$idx" >&2
      return 2
      ;;
    esac
    if [[ "$seen" == *" $id "* ]]; then
      printf -- '--diff: %s has duplicate id: %s\n' "$source" "$id" >&2
      return 2
    fi
    seen="$seen$id "
    printf '%s %s\n' "$id" "$status"
    idx=$((idx + 1))
  done <<<"$split_rows"
}

_diff_lookup_status() {
  local rows="$1" ident="$2" row rid status
  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    rid="${row%% *}"
    status="${row#* }"
    if [[ "$rid" == "$ident" ]]; then
      printf '%s' "$status"
      return 0
    fi
  done <<<"$rows"
  printf ''
}

emit_diff() {
  # Compare current run's JSON_ROWS against the JSON file at $DIFF_PATH.
  # Prints one line per change. Exits 0 on no changes, 1 on any change,
  # 2 on parse error. Runtime stays stock-shell only (no python3/jq/node).
  local current_body prev_pairs curr_pairs ids ident p c marker changes
  current_body=$(
    IFS=,
    echo "${JSON_ROWS[*]:-}"
  )
  prev_pairs=$(_diff_parse_rows "previous" <"$DIFF_PATH") || exit 2
  curr_pairs=$(printf '{"results":[%s]}' "$current_body" | _diff_parse_rows "current") || exit 2

  ids=$(printf '%s\n%s\n' "$prev_pairs" "$curr_pairs" | awk 'NF {print $1}' | sort -u)
  changes=0
  while IFS= read -r ident; do
    [[ -z "$ident" ]] && continue
    p=$(_diff_lookup_status "$prev_pairs" "$ident")
    c=$(_diff_lookup_status "$curr_pairs" "$ident")
    [[ "$p" == "$c" ]] && continue
    changes=$((changes + 1))
    if [[ -z "$p" ]]; then
      printf '+ %s\t(new)        %s\n' "$ident" "$c"
    elif [[ -z "$c" ]]; then
      printf -- '- %s\t(removed)    was %s\n' "$ident" "$p"
    else
      marker="~"
      case "$p->$c" in
      pass-\>warn | pass-\>fail | warn-\>fail | skip-\>warn | skip-\>fail) marker="^" ;;
      fail-\>warn | fail-\>pass | warn-\>pass | warn-\>skip | fail-\>skip) marker="v" ;;
      esac
      printf '%s %s\t%s -> %s\n' "$marker" "$ident" "$p" "$c"
    fi
  done <<<"$ids"

  if [[ "$changes" -eq 0 ]]; then
    echo "no posture changes"
    exit 0
  fi
  exit 1
}

emit_summary() {
  # ═════════════════════════════════════════════════════════════════════════════
  # Summary
  # ═════════════════════════════════════════════════════════════════════════════
  if [[ -n "${DIFF_PATH:-}" ]]; then
    emit_diff
  fi
  if [[ "$MODE" == "json" ]]; then
    JSON_BODY=""
    if [[ ${#JSON_ROWS[@]} -gt 0 ]]; then
      JSON_BODY=$(
        IFS=,
        echo "${JSON_ROWS[*]}"
      )
    fi
    # Escape top-level string fields uniformly. Hostnames in practice don't
    # contain " or \, but the JSON producer should not assume that — and the
    # row-level _record path already escapes, so top-level should too.
    JSON_HOST=$(_json_escape "$(redact host "$(hostname)")")
    JSON_MACOS=$(_json_escape "$MACOS_VER")
    JSON_ARCH=$(_json_escape "$ARCH")
    printf '{\n  "host":"%s","macos":"%s","arch":"%s",\n  "summary":{"pass":%d,"warn":%d,"fail":%d,"skip":%d},\n  "results":[\n    %s\n  ]\n}\n' \
      "$JSON_HOST" "$JSON_MACOS" "$JSON_ARCH" \
      "$PASS_N" "$WARN_N" "$FAIL_N" "$SKIP_N" \
      "$JSON_BODY"
    [[ "$FAIL_N" -gt 0 ]] && exit 1 || exit 0
  fi

  echo
  printf "%s━━━ Summary ━━━%s\n" "$BOLD" "$NC"
  printf "  %s✅ Pass:%s  %d\n" "$GREEN" "$NC" "$PASS_N"
  printf "  %s⚠️  Warn:%s  %d\n" "$YELLOW" "$NC" "$WARN_N"
  printf "  %s❌ Fail:%s  %d\n" "$RED" "$NC" "$FAIL_N"
  printf "  %s⏭  Skip:%s  %d  %s(checks not applicable / require sudo / unreadable)%s\n" "$DIM" "$NC" "$SKIP_N" "$DIM" "$NC"

  if [[ "$FAIL_N" -gt 0 || "$WARN_N" -gt 0 ]]; then
    echo
    printf "%sTop items to address:%s\n" "$BOLD" "$NC"
    i=0
    if [[ ${#RESULTS_FAIL[@]} -gt 0 ]]; then
      for r in "${RESULTS_FAIL[@]}"; do
        i=$((i + 1))
        [[ $i -gt 10 ]] && break
        printf "  %s%d.%s %s\n" "$RED" "$i" "$NC" "$r"
      done
    fi
    if [[ ${#RESULTS_WARN[@]} -gt 0 ]]; then
      for r in "${RESULTS_WARN[@]}"; do
        i=$((i + 1))
        [[ $i -gt 10 ]] && break
        printf "  %s%d.%s %s\n" "$YELLOW" "$i" "$NC" "$r"
      done
    fi
  fi

  echo
  printf "%sDone. Re-run after each change to track progress.%s\n" "$DIM" "$NC"

  [[ "$FAIL_N" -gt 0 ]] && exit 1 || exit 0
}

main() {
  parse_args "$@"
  detect_runtime
  init_colors
  print_header
  run_all_sections
  emit_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

# Contributing

Thanks for the interest. The project is small and stays that way deliberately. A few hard rules and a few "this will save you a round-trip in review" gotchas.

## Hard rules

These are CI-enforced; PRs that violate them will not merge.

1. **Read-only.** The script never modifies any file, plist, defaults key, launchd job, or system setting. `scripts/check-read-only.sh` is a tripwire over command-position uses of mutating commands (`rm`, `mv`, `chmod`, `defaults write`, `plutil -replace`, mutating `launchctl`, package installs, `curl|bash`, …). If a new check genuinely needs a probe the tripwire blocks, it lives behind a narrow allowlist with positive *and* negative fixtures under `tests/check-read-only/`. The current allowlists are `sqlite3 -readonly` (TCC.db), read-only-verb `osascript` (login items), bare `brew tap` (listing), the NextDNS `curl` probe, and `gh auth status` — all `--network`-gated where they reach out.

2. **Bash 3.2 compatible.** Stock macOS ships `/bin/bash` 3.2.57. No associative arrays, no `${var^^}`, no `&>` (use `>foo 2>&1`), no `mapfile`. Use parallel arrays + linear scans where you'd reach for an associative array. Use `${arr[@]+"${arr[@]}"}` whenever expanding a potentially-empty array under `set -u`.

3. **Stock-macOS tools only.** `bash`, `awk`, `sed`, `grep`, `defaults`, `plutil`, `pgrep`, `pmset`, `tmutil`, `csrutil`, `spctl`, `fdesetup`, `dscl`, `sw_vers`, `system_profiler`, `socketfilterfw`, `systemextensionsctl`, `scutil`, `softwareupdate`, `profiles`, `sqlite3 -readonly`, `osascript` (read-only verbs), `bputil`, `python3` (for `--diff` and the schema validator only — `python3` is part of macOS; `pip install` is not required and must not become a runtime dependency). No Homebrew packages, no `jq`, no Node.

4. **Stable check IDs.** Every emitted row carries an `id` matching grammar `<area>.<subject>.<fact>` (fixed) or `<area>.<subject>.<instance>` (templated). Fixed IDs go in `tests/fixtures/expected_ids.txt`; templated patterns go in `tests/fixtures/expected_id_patterns.txt`. IDs are unique within a single run (the script exits 2 on a duplicate at runtime) and stable across runs so `--diff` works. Renaming an ID is a breaking change; bump the major version of the JSON schema (see `docs/schema.md`).

## Gotchas (real bugs we've already hit)

- **Composites reading profile-overridden constituents must accept `warn|fail`.** `_apply_profile` rewrites constituent statuses *before* `STATUS_BY_ID` is updated, so a composite like `ssh.posture` that reads `_status_of "ssh.keys.unencrypted"` sees the post-profile value. Predicates of the form `[[ "$x" == "warn" ]]` silently miss the fail-escalated case under `--profile=web3 / paranoid / developer` — exactly the case the stricter profile was meant to catch. Always use `case "$x" in warn|fail) ... ;; esac`.
- **Rows that embed identifying values into labels must branch on `$REDACT`.** Hostnames, VPN brands, system-extension bundle IDs, AV brands, wallet brands, Time Machine destination names, app inventory — anything that varies between two same-config Macs of the same threat profile must collapse to a count or category under `--redact`. Status-only changes (pass↔warn↔fail) are always safe; `${variable}` interpolation usually isn't. The `tests/integration/redaction.bats` smoke suite asserts absence of known leak tokens.
- **The audit exits 1 when any FAIL row is emitted.** That's the normal "I found problems" signal, not a runtime error. Test harnesses that run the script end-to-end need `|| true` around the invocation.
- **`pgrep` patterns are ERE.** macOS `pgrep` does not honour BRE-style `\|` alternation. Use `_proc_running "a|b"`, not `pgrep -qi "a\|b"`. A regression test asserts no `\|` in pgrep calls.
- **`shopt` is process-global.** Section-local glob behaviours (`nullglob`, `extglob`, …) must save the caller's state and restore on exit.

## Running the test suite

```bash
brew install bats-core shellcheck shfmt
bash -n mac-posture-audit.sh
/bin/bash -n mac-posture-audit.sh   # explicit Bash 3.2 check
shellcheck -S warning mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
shfmt -d -i 2 mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
./scripts/check-read-only.sh
bats tests/sections tests/integration
```

CI runs all of the above on `macos-latest` plus the JSON smoke + schema validator + the strengthened redaction smoke + the tripwire positive/negative fixture suite.

## Adding a new check

1. Pick an ID following the grammar. If it's templated, add the pattern to `tests/fixtures/expected_id_patterns.txt`; if it's fixed, add the literal to `tests/fixtures/expected_ids.txt`.
2. Write the probe in the appropriate `section_NN_*` function. Read-only probes only; if the data lives behind sudo, gate with `if ! $QUICK; then ...; sudo -n <read-only-probe>; fi` and skip cleanly when sudo isn't available.
3. Emit a single row with `pass`/`warn`/`fail`/`skip` carrying the ID. Use a short, declarative label that round-trips through `--redact`. Hint text should suggest a concrete next action.
4. If the row embeds any `$variable`, branch on `$REDACT` (see Gotchas above).
5. Add a bats test under `tests/sections/`. Mock any CLI the check calls with `mock_cli_script` from `tests/helpers.bash`. Assert the recorded status and label.
6. If the check is meant to escalate under a profile, add an entry to `PROFILE_OVERRIDES` and cover it in `tests/integration/profile.bats`.

## PRs

- Open an issue first for substantive changes — a new section, a schema addition, a profile override change, anything that touches the tripwire allowlists. For small fixes (a brittle regex, a missed redact branch, a stale comment) just open the PR.
- Explain the threat model the check addresses. "This catches X. The current rows miss it because Y. Composite alternatives in §3 of docs/AGENTS.md don't cover this because Z." A check the audit doesn't have today is a fine PR; the script is intentionally conservative about adding noise.
- Commits and tags are SSH-signed. Signing your own commits isn't required to contribute; it just looks nicer in the log.
- The project's MIT-licensed; by contributing you're agreeing to license your changes the same way.

## Out of scope

- Remediation. The audit reports posture; a separate companion tool can remediate if anyone wants to write one. Mixing observation and mutation in one binary is the wrong trust posture.
- Malware scanning. Use Bitdefender / Malwarebytes / Objective-See tools; that's their job.
- Cross-platform (Linux, Windows). The macOS-specific CLI calls go too deep.
- Network probes by default. Anything that touches a remote service is `--network`-gated.
- Bash 4+ syntax. We will not require `brew install bash` to run the audit.

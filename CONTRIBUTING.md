# Contributing

Contributions are welcome, including independent security review, macOS compatibility fixtures, documentation corrections and false-positive fixes. The audit keeps a small, read-only runtime.

## Feedback and first contributions

Use [GitHub issues](https://github.com/demirelo/mac-posture-audit/issues) for
bugs and feature proposals, and pull requests for changes. English reports and
comments are welcome. Read [SECURITY.md](SECURITY.md#reporting-a-vulnerability)
before reporting a possible vulnerability; use its private reporting channel.

Start with a narrow, reproducible correction: a wrong status, a missing error
case, an outdated help example or a synthetic compatibility fixture. State the
check ID, expected behavior and why the existing signal is insufficient. Keep
new fixtures synthetic. Do not attach a real host report, screenshot, credential,
private path, company configuration or inventory. Redaction alone does not make
a host report anonymous.

The maintainer triages proposals, discusses scope, reviews the patch and checks
CI before merge. A proposal can be declined; explain a material compatibility or
security concern so a contributor can revise it. Contributors can review and
comment on public PRs without first receiving repository write access.

## Human review and ownership

`demirelo` is the current maintainer and code owner. CODEOWNERS requests that
owner's review for eligible external PRs. It does not prove that review happened.
Independent human reviewers are welcome, particularly for execution boundaries,
report parsing/writes, redaction and macOS compatibility.

A human review should examine the patch and use the
[review checklist](docs/review-checklist.md). AI analysis and green CI are useful
inputs, but do not count as an independent human approval. Do not post an
approval automatically or add a review trailer for a review that did not occur.

GitHub does not permit authors to approve their own PRs. Owner-authored PRs need
a different human for independent review credit. This project currently has one
maintainer; the missing second reviewer remains a disclosed gap. Required CI and
other branch protections remain enforced. A second maintainer must be identified
and accepted before changing repository access or requiring approvals that the
current team cannot supply.

## Hard rules

These are CI-enforced; PRs that violate them will not merge.

1. **Read-only.** Probes never modify settings or configuration. The explicit `--snapshot` option may create private report storage; this is the sole audit-script write exception. `scripts/check-read-only.sh` is a tripwire over command-position uses of mutating commands (`rm`, `mv`, `chmod`, `defaults write`, `plutil -replace`, mutating `launchctl`, package installs, `curl|bash`, …). If a new check genuinely needs a probe the tripwire blocks, it lives behind a narrow allowlist with positive *and* negative fixtures under `tests/check-read-only/`. The current allowlists are `sqlite3 -readonly -init /dev/null` (TCC.db), read-only-verb `osascript` (login items), the NextDNS `curl` probe, and `gh auth status` — all `--network`-gated where they reach out.

2. **Bash 3.2 compatible.** Stock macOS ships `/bin/bash` 3.2.57. No associative arrays, no `${var^^}`, no `&>` (use `>foo 2>&1`), no `mapfile`. Use parallel arrays + linear scans where you'd reach for an associative array. Use `${arr[@]+"${arr[@]}"}` whenever expanding a potentially-empty array under `set -u`.

3. **Stock-macOS tools only.** `bash`, `awk`, `sed`, `grep`, `defaults`, `plutil`, `pgrep`, `pmset`, `tmutil`, `csrutil`, `spctl`, `fdesetup`, `dscl`, `sw_vers`, `system_profiler`, `socketfilterfw`, `systemextensionsctl`, `scutil`, `softwareupdate`, `profiles`, `sqlite3 -readonly -init /dev/null`, `osascript` (read-only verbs), `bputil`. The audit, diff, and trend paths do not require Python. Optional report rendering and tests use Python 3 with its standard library. No Homebrew packages, no `jq`, no Node.

4. **Stable check IDs.** Every emitted row carries an `id` matching grammar `<area>.<subject>.<fact>` (fixed) or `<area>.<subject>.<instance>` (templated). Fixed IDs go in `tests/fixtures/expected_ids.txt`; templated patterns go in `tests/fixtures/expected_id_patterns.txt`. IDs are unique within a single run (the script exits 2 on a duplicate at runtime) and stable across runs so `--diff` works. Renaming an ID is a breaking change; bump the major version of the JSON schema (see `docs/schema.md`).

## Execution boundary

Run the script as a normal user. Each privileged probe uses `sudo -n`; do not run a complete audit as root. Do not add package-manager CLI calls: configuration queries can load project code. Inspect settings as data and state what remains unverified. Keep the single-file Bash 3.2 runtime and the stable row IDs.

The safety checker is a static tripwire, not a shell parser or a sandbox. Add positive and negative fixtures for each accepted syntax. Review command arguments and control flow as well as checker results.

## Gotchas (real bugs we've already hit)

- **Composites reading profile-overridden constituents must accept `warn|fail`.** `_apply_profile` rewrites constituent statuses *before* `STATUS_BY_ID` is updated, so a composite like `ssh.posture` that reads `_status_of "ssh.keys.unencrypted"` sees the post-profile value. Predicates of the form `[[ "$x" == "warn" ]]` silently miss the fail-escalated case under `--profile=web3 / paranoid / developer` — exactly the case the stricter profile was meant to catch. Always use `case "$x" in warn|fail) ... ;; esac`.
- **Rows that embed identifying values into labels must branch on `$REDACT`.** Hostnames, VPN brands, system-extension bundle IDs, AV brands, wallet brands, Time Machine destination names, app inventory — anything that varies between two same-config Macs of the same threat profile must collapse to a count or category under `--redact`. Status-only changes (pass↔warn↔fail) are always safe; `${variable}` interpolation usually isn't. The `tests/integration/redaction.bats` smoke suite asserts absence of known leak tokens.
- **The audit exits 1 when any FAIL row is emitted.** That's the normal "I found problems" signal, not a runtime error. Test harnesses that run the script end-to-end need `|| true` around the invocation.
- **`pgrep` patterns are ERE.** macOS `pgrep` does not honour BRE-style `\|` alternation. Use `_proc_running "a|b"`, not `pgrep -qi "a\|b"`. A regression test asserts no `\|` in pgrep calls.
- **`shopt` is process-global.** Section-local glob behaviours (`nullglob`, `extglob`, …) must save the caller's state and restore on exit.

## Running the test suite

```bash
brew install bats-core shellcheck shfmt
./scripts/test.sh
```

CI runs the same entry point on `macos-latest`. It covers section fixtures, real quick-mode host smoke tests with a temporary HOME, JSON schema checks, redaction cases, hostile reports, snapshot permissions, and safety-checker fixtures.

## Adding a new check

1. Pick an ID following the grammar. If it's templated, add the pattern to `tests/fixtures/expected_id_patterns.txt`; if it's fixed, add the literal to `tests/fixtures/expected_ids.txt`.
2. Write the probe in the appropriate `section_NN_*` function. Read-only probes only; if the data lives behind sudo, gate with `if ! $QUICK; then ...; sudo -n <read-only-probe>; fi` and skip cleanly when sudo isn't available.
3. Emit a single row with `pass`/`warn`/`fail`/`skip` carrying the ID. Use a short, declarative label that round-trips through `--redact`. Hint text should suggest a concrete next action.
4. If the row embeds any `$variable`, branch on `$REDACT` (see Gotchas above).
5. Add a bats test under `tests/sections/`. Mock any CLI the check calls with `mock_cli_script` from `tests/helpers.bash`. Assert the recorded status and label.
   - **If the check reads from `/Applications`, `$HOME`, or a system plist, parameterise the path via an overridable env array** (`APP_ROOTS`, `IDE_APP_ROOTS`, `VPN_KILLSWITCH_ROOTS`, `WIFI_KNOWN_PLISTS`, `SANDBOX_CLI_BINS` are the established names). Default to the production path; tests override to a `$BATS_TEST_TMPDIR` sandbox. Otherwise the test's outcome depends on what the developer happens to have installed — flaky CI, flaky local runs, and worse, false confidence.
   - **If the check is non-trivial, factor it into a `_check_<thing>` helper** that the section delegates to. Tests can then call the helper directly without having to mock the entire surrounding section. Examples in the codebase: `_check_vpn_killswitch`, `_check_supply_direnv`, `_check_supply_pip_extra_index`, `_check_supply_uv_config`, `_check_wifi_known_networks`.
6. If the check is meant to escalate under a profile, add an entry to `PROFILE_OVERRIDES` and cover it in `tests/integration/profile.bats`. The `founder` profile is an explicit union of `developer` + `web3` (kept verbatim in the override table rather than computed), so any new entry that lands in `developer` OR `web3` should also land in `founder`.

## PRs

- Open an issue first for substantive changes — a new section, a schema addition, a profile override change, anything that touches the tripwire allowlists. For small fixes (a brittle regex, a missed redact branch, a stale comment) just open the PR.
- Explain the threat model the check addresses. "This catches X. The current rows miss it because Y. Composite alternatives in §3 of docs/AGENTS.md don't cover this because Z." A check the audit doesn't have today is a fine PR; the script is intentionally conservative about adding noise.
- Signed commits are welcome but are not required to contribute. Verify release signatures against the documented signer; do not assume every source commit is signed.
- The project's MIT-licensed; by contributing you're agreeing to license your changes the same way.

## Out of scope

- Remediation. The audit reports posture; a separate companion tool can remediate if anyone wants to write one. Mixing observation and mutation in one binary is the wrong trust posture.
- Malware scanning. Use Bitdefender / Malwarebytes / Objective-See tools; that's their job.
- Cross-platform (Linux, Windows). The macOS-specific CLI calls go too deep.
- Network probes by default. Anything that touches a remote service is `--network`-gated.
- Bash 4+ syntax. We will not require `brew install bash` to run the audit.

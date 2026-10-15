# mac-posture-audit

[![Safety](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml/badge.svg?branch=main)](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/demirelo/mac-posture-audit/badge)](https://scorecard.dev/viewer/?uri=github.com/demirelo/mac-posture-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Bash 3.2 compatible](https://img.shields.io/badge/bash-3.2%20compatible-blue)](#compatibility)

A read-only, single-file shell script that audits a macOS machine's security posture and prints a colored report. Uses stock macOS tools. Default scans do not change files or settings. The optional snapshot command saves a local report.

## Install

```bash
git clone https://github.com/demirelo/mac-posture-audit
cd mac-posture-audit
```

Use the [latest signed release](https://github.com/demirelo/mac-posture-audit/releases/latest)
for a versioned download. Releases include a SHA-256 checksum, a Sigstore bundle,
and build provenance. The Homebrew tap is not published; its draft formula is
in [`packaging/homebrew/`](packaging/homebrew/).

## Privacy and report handling

The default audit is offline. It reads local settings and prints results; it has
no telemetry, report upload, or remote analysis service. Use `--offline` to state
that choice explicitly. `--network` permits the two documented external probes;
it is not required for the local checks.

`--redact` reduces identifying details, but a report still describes security
settings and installed software. Review it before sharing. Keep host reports,
snapshots, screenshots, credentials, and private configuration out of commits,
issues, CI artifacts, and external AI prompts. The HTML renderer works locally
and loads no external assets.

```bash
umask 077
./mac-posture-audit.sh --offline --json --redact --profile normal > posture.json
/usr/bin/python3 tools/render_report.py posture.json --output report.html
```

The renderer refuses an existing output path. Use a new filename for each run.
No real host report is needed for CI; tests and fuzzing use synthetic inputs.

## Inspect before running

Don't run security tooling on trust alone — it's one shell script, so read it first.

```bash
git clone https://github.com/demirelo/mac-posture-audit
cd mac-posture-audit

less mac-posture-audit.sh          # 1. Read it — the whole tool is one file.
/bin/bash -n mac-posture-audit.sh  # 2. Syntax-check on stock macOS Bash 3.2.
./scripts/check-read-only.sh       # 3. CI-enforced tripwire: fails on any mutating
                                   #    command or un-opted-in network call.
shasum -a 256 mac-posture-audit.sh # 4. Pin a checksum for later re-pulls.
```

The tripwire has regression tests (`tests/check-read-only/should_{pass,fail}/`). Release tags can be verified with their signing key; `git tag -v` only means something once you've trusted the signer's key out-of-band (GitHub publishes pubkeys at `/<user>.keys`). See [SECURITY.md](./SECURITY.md) for probe restrictions, their limits, and the narrow `sqlite3 -readonly -init /dev/null` / read-only-verb `osascript` exceptions.

See [Scorecard maintenance](docs/scorecard.md) for the dated score, scan repair, and remaining review requirements.

## What it checks

30 sections with 184 fixed check IDs, plus instance-specific IDs. The number of
rows in a run depends on the OS and installed software. Checks by theme:

- **System integrity** — SIP, Gatekeeper, FileVault, Apple Silicon Secure Boot, third-party kernel extensions.
- **Login & privacy** — auto-login, screen-lock delay, Touch ID for sudo, Apple ads/analytics, Lockdown Mode.
- **Network** — firewall & stealth, sharing services, AirDrop/Bluetooth/Wi-Fi exposure, DNS/DoH & VPN (incl. killswitch), proxies/PAC/WPAD, `/etc/hosts`, 16 AV/EDR engines, outbound monitors (Little Snitch / LuLu).
- **Browsers & extensions** — installed/default browser, bundle-version staleness, profile counts, plus a Chromium/Safari/Firefox extension inventory that flags protective, wallet, and transaction-simulator add-ons.
- **Developer & supply chain** — npm/yarn/pnpm `ignore-scripts`, supply-chain scanners, `.npmrc` and registry rewrites, `gh` / git credential helpers, `extra-index-url` dependency-confusion risk, Homebrew taps, IDE workspace trust + folder-open task autorun + trusted-folder sprawl, plaintext registry tokens on disk (npm/PyPI/cargo/gem), and a `supply.blast_radius` composite that answers "if a malicious dependency install runs code here, how far can it reach?"
- **Credentials & secrets** — credential patterns in shell rc files, `.env` and sensitive dotfiles, SSH key encryption + agent, git signing.
- **Crypto & 2FA** — hardware wallets (Ledger / Trezor / Keystone / GridPlus), password managers, YubiKey / FIDO2, and a wallet-isolation composite.
- **Backups & cloud** — Time Machine destinations / recency / encryption, third-party backup tools, iCloud sync, and sensitive data (`.ssh` / `.aws` / wallets) leaking into cloud-sync roots.
- **Persistence & access** — LaunchAgents/Daemons (incl. webhook/exfil-shaped destinations), login items, crontab, TCC permission holders, remote-access apps, sandboxes, MDM enrollment, clipboard managers.
- **Agents & MCP** — MCP servers (Cursor / Claude / Windsurf / Gemini): server count, `@latest`/`:latest` unpinned launchers, remote HTTP/SSE transports, dynamic launchers (npx/uvx/bunx/pipx/docker), filesystem-capable servers, and webhook/exfil destinations. MCP credential values and key names are omitted from reports.
- **AI agent instruction hygiene** — discovers the files that steer coding agents (`AGENTS.md` / `CLAUDE.md` / `GEMINI.md` / `.cursorrules` / `.cursor` rules, etc.) under your project roots and flags hidden/zero-width Unicode, suspicious directive-shaped phrases (prompt-injection / pipe-to-shell), and webhook destinations. Two-tier discovery with strict bounds (depth 3, ≤256 KB/file, ≤200 files, junk dirs pruned); matched lines, URLs, and tokens are never printed.
- **Webhook / exfil shapes** — one-line exfil endpoints (Discord/Slack/Telegram/webhook.site/RequestBin/Pipedream/IFTTT/Zapier) detected across config surfaces that run automatically — shell rc, LaunchAgents, MCP configs, agent instruction files, `~/.npmrc` / `~/.pypirc` — aggregated into `config.webhook_exfil_shape`. Provider name only; never the URL or token.
- **Inventory (catalog-driven)** — browser extensions, editor extensions (VS Code / Cursor / Windsurf / VSCodium), and MCP server IDs, each matchable against an exposure catalog of known-bad IDs.
- **Attack chains** — named cross-section composites that fire only when a full attack path is assembled: `chain.fake_interview` (IDE auto-runs untrusted code + no sandbox), `chain.wallet_drain` (wallet + no isolation + no outbound monitor), `chain.agent_exposure` (a filesystem/remote MCP agent on the same machine as a wallet), `chain.cloud_exfil` (SSH keys / wallet data / dotfiles under a cloud-sync root), `chain.supply_to_wallet` (a poisoned dependency install reaching an unisolated wallet), `chain.agent_supply_chain` (an agent/IDE/MCP surface that can reach registry tokens, SSH keys, or a wallet).

Several checks are composites that fold multiple rows into a single verdict (`system.theft_resistance`, `backup.recovery_path`, `ssh.posture`, `users.crypto_isolation_indicator`, the `chain.*` attack chains, …). The canonical check list is [tests/fixtures/expected_ids.txt](tests/fixtures/expected_ids.txt); composite patterns and agent-review guidance live in [docs/AGENTS.md](docs/AGENTS.md).

Every run ends with an **Executive Verdict** — a profile-aware one-line read plus an `Action priority:` level — and a **Top risks to address** list that ranks the findings that actually matter for your threat model (`urgent` > `high` > `medium` > `low`) instead of dumping them in scan order. Both appear in the JSON too (`executive_verdict`, ranked `top_risks`). See [Top risks & verdict](#top-risks--verdict).

## Usage

```bash
./mac-posture-audit.sh                                        # default: offline, read-only
./mac-posture-audit.sh --network                              # opt-in live checks (NextDNS routing, gh auth)
./mac-posture-audit.sh --json --quick --redact > posture.json # redacted local report; review before sharing
```

Run the audit as your normal user. Whole-script root execution is rejected. Without `--quick`, individual checks use `sudo -n` if access is already available; the audit does not ask for a password. A failed privileged read is unverified, not a pass. The default run is offline; `--network` permits the two documented network probes.

| Flag | Effect |
|---|---|
| `--quick` | Skip checks that require sudo |
| `--json` | Machine-readable JSON output |
| `--network` | Allow live external probes (NextDNS live-routing, `gh auth status`). Default off. |
| `--offline` | Explicit no-external-calls (already the default) |
| `--redact` | Mask hostname, emails, usernames, resolver IPs, `$HOME` paths, and brand names. Use when sharing. |
| `--profile NAME` | Severity calibration: `normal` (default), `web3`, `paranoid`, `developer`, `founder`, `journalist`. `--profile auto` detects signals, recommends a profile, and exits. See [Profiles](#profiles). |
| `--diff PATH` | Compare against a saved `--json` run; print one line per id whose status changed. |
| `--exposure-catalog PATH` | Load a deny-list of known-bad extension/MCP/brew/bundle IDs. See [Exposure catalogs](#exposure-catalogs). |
| `--summary-line` | Append one parseable summary line: `… pass=N warn=N fail=N skip=N`. Combines with `--json`. |
| `--top N` | Cap the "Top risks to address" list to N items (0–1000; default 7). `--top 0` hides the list but keeps the Executive Verdict. |
| `--explain ID` | Print the threat rationale + per-profile severity for one check id (e.g. `chain.fake_interview`) and exit, without scanning. |
| `--report md` | Render a shareable Markdown report (Executive Verdict + Top risks + full results table) instead of the terminal report. Honors `--redact`. |
| `--snapshot` | Append a redacted JSON snapshot to `~/.mac-posture-audit/history/` (implies `--redact`). The only write the tool performs; default runs are read-only. |
| `--trend` | Read-only: summarize how posture changed across stored snapshots (oldest vs newest). |
| `--selftest` | Run a hermetic end-to-end smoke test and exit. Non-zero = the install can no longer detect what it should. |
| `--version` / `--help` | Show version / usage and exit |

Exit code: `0` if no failures, `1` if any check fails, `2` if the script itself errors.

### Probe safety and scope

The audit reads npm, pnpm, and Yarn user configuration as data. It does not execute package managers, Homebrew, or Gitleaks. Project plugins and launchers cannot run through these probes. Package-policy results describe user configuration; project, environment, and version-specific overrides remain unverified. An absent user policy produces `skip`, because defaults differ by version. See [Yarn configuration](https://yarnpkg.com/configuration/yarnrc#yarnPath) for project executable selection and script settings. Homebrew tap inventory covers standard installation directories; analytics require a manual check.

Direct execution uses system Bash with startup-file and imported-function loading disabled. System commands take priority over package-manager paths. The optional `gh auth status` probe still requires trust in the installed GitHub CLI. These controls do not make a compromised Mac trustworthy.

### Profiles

`--profile NAME` escalates specific checks past their default severity for a given threat model. The check still runs unchanged — only its resulting `status` is rewritten before being counted and printed, and a profile can never downgrade a `fail`.

| Profile | Focus |
|---|---|
| `normal` | defaults — no escalation |
| `web3` | wallet / key / supply-chain exposure → `fail` (wallet on main user, unencrypted SSH key, `ignore-scripts=false`, missing scanner or tx-simulator, wallet in cloud sync, remote-access app, stale browser, VPN killswitch off, IDE trust off) |
| `paranoid` | everything in `web3`, plus Bluetooth/AirDrop exposure, weak firewall/stealth, stale or unencrypted Time Machine, missing auto-updates, plaintext Docker auth, `extra-index-url` |
| `developer` | supply-chain + secret hygiene → `fail` (`ignore-scripts`, missing scanner, `extra-index-url`, shell-rc credentials) |
| `founder` | union of `developer` + `web3` — solo founders shipping their own code who also custody crypto |
| `journalist` | nation-state spyware lens — Lockdown Mode off is surfaced; Bluetooth/AirDrop, telemetry, remote access, browser debugging, VPN killswitch, and stale software all `fail` |
| `auto` | not an escalation profile — detects signals (IDEs, dev toolchains, wallet apps/extensions), prints a recommended profile, and exits |

The exact override matrix is `PROFILE_OVERRIDES` in [mac-posture-audit.sh](mac-posture-audit.sh) — each entry is `profile|id|from_status|to_status` and only fires when the check actually emits `from_status`.

### JSON output

Each row carries a stable `id`, `status`, `label`, and `hint`. IDs are unique within a run and stable across runs, so consumers can diff successive scans by `id`:

```json
{
  "host":"<HOST>","macos":"26.4.1","arch":"arm64",
  "summary":{"pass":1,"warn":1,"fail":0,"skip":0,"total":2},
  "executive_verdict":{"profile":"founder","tier":"medium","text":"Review the warning below.","top_counts":{"urgent":0,"high":0,"medium":1,"low":0}},
  "top_risks":[
    {"rank":1,"id":"network.firewall.stealth","status":"warn","tier":"medium","effort":"low","label":"Firewall stealth mode is off","hint":"Firewall Options → Enable stealth mode"}
  ],
  "results":[
    {"id":"system.sip.enabled","status":"pass","label":"SIP (System Integrity Protection) is enabled","hint":""},
    {"id":"network.firewall.stealth","status":"warn","label":"Firewall stealth mode is off","hint":"Firewall Options → Enable stealth mode"}
  ]
}
```

`executive_verdict`, `top_risks`, and `summary.total` are additive (non-breaking) top-level fields. ID grammar is `<area>.<subject>.<fact>` (or `.<instance>` for templated checks like `network.sharing.<service>`). CI gates the full id set against [tests/fixtures/expected_ids.txt](tests/fixtures/expected_ids.txt) and dynamic patterns against [expected_id_patterns.txt](tests/fixtures/expected_id_patterns.txt). Full schema (field types, status enum, versioning) is in [docs/schema.md](docs/schema.md).

`--diff PATH` compares the current run against a saved `--json` output and prints only the rows whose status changed (exit `0` if none differ, `1` if any, `2` on file/parse error). Combine with cron + `--profile` to track posture over time.

```
^ ext.wallet            warn -> fail        (escalation)
v ssh.keys.unencrypted  warn -> pass        (resolved)
+ persist.user.launchagents  (new)  warn    (new check or condition appeared)
- av.engine.detected   (removed)  pass     (no longer emitted this run)
```

### Top risks & verdict

The audit doesn't just list findings — it tells you which ones can actually hurt you first. After the per-section rows and the flat Summary counts, every run prints:

- an **Executive Verdict** — profile-aware, calm (it never cries "compromised" when nothing failed), with an `Action priority:` level derived from the highest-severity finding present and your concentration of risk;
- **Top risks to address** — the warn/fail rows ranked by action priority, not scan order.

Tiers map to action, not drama:

| Tier | Meaning |
|---|---|
| `urgent` | a `fail` on a high-blast row, or a fully-assembled `chain.*` |
| `high` | any other `fail`, or a `warn` your profile cares about (wallet / dev / MCP / backup) |
| `medium` | an ordinary `warn` |
| `low` | optional / cosmetic hardening |

Each risk also carries a remediation **effort** (`low` = flip a setting, `high` = structural work like a new user account or migrating a wallet), so high-impact / low-effort wins stand out — text shows `[tier · effort]`, JSON adds an `effort` field. The reorder is the point: on a `--profile founder` Mac, wallet exposure and a missing recovery path rise above "firewall not in block-all mode." `--top N` caps the list (`--top 0` keeps just the verdict); `--explain <id>` prints the threat model behind a specific check. The same data is in the JSON (`executive_verdict`, ranked `top_risks`); the deeper per-finding narrative for an LLM reviewer stays in [docs/AGENTS.md](docs/AGENTS.md).

### Sharing & trends

The audit is read-only by default, but a few opt-in companions make the report portable and longitudinal:

```bash
./mac-posture-audit.sh --report md --redact > posture.md            # local Markdown (honors --redact)
./mac-posture-audit.sh --json --redact | /usr/bin/python3 tools/render_report.py --output report.html   # self-contained HTML, no deps
./mac-posture-audit.sh --snapshot                          # append a redacted JSON to ~/.mac-posture-audit/history/
./mac-posture-audit.sh --trend                             # summarize improved/regressed checks across snapshots
```

`--snapshot` is the only write in the audit script. It creates a private directory (`0700`) and a new file (`0600`). It rejects unsafe directory permissions, access-granting ACLs, and user-controlled symlinks. It never overwrites an existing snapshot. A failed write exits `2`; an interrupted write can leave an incomplete file. `MSA_HISTORY_DIR` can select another absolute, private directory. Review older history directories before setting their permissions to `0700`.

`--trend` reports improvements, regressions, added and removed checks, and changes in verification coverage. A change to `skip` does not count as an improvement. Invalid history data exits `2`.

`tools/render_report.py` is an optional Python 3 companion with no third-party dependencies. Its `--output` option creates a new private file and refuses existing files and symlinks. On macOS it removes inherited ACLs from that new file before writing. It validates report fields and counts, escapes HTML, and uses no external assets. Python is not required by the audit script. Reports remain sensitive after redaction; review them before sharing. For a maintained deny-list, point `--exposure-catalog` at [`catalog/known-bad.txt`](catalog/known-bad.txt) and refresh it via `git pull`.

### Exposure catalogs

`--exposure-catalog PATH` loads a deny-list of known-bad identifiers that the inventory checks (browser/editor extensions, MCP servers) consult. The catalog ships *separately from the script*, so a new wallet-drainer extension ID or compromised release can be added without rev'ing the audit:

```
# category|name|severity[|id]   (lines starting with # are comments)
browser_extension_id|fakeextensionidaaaaaaaaaaaaaaaaaa|critical|drainer-2026-001
editor_extension|malicious.publisher|warn|advisory-2026-042
mcp_server|untrusted-remote-mcp|critical|campaign-x-2026
```

- **Categories**: `browser_extension_id`, `editor_extension`, `mcp_server`, `mcp_package`, `app_bundle_id`, `brew_formula`.
- **Severity**: `info` (→ `skip`), `warn`, `critical` (→ `fail`).
- Matching is case-insensitive on the name; unknown categories/severities are silently dropped; an unreadable catalog exits `2`.

The pipe-delimited format is heuristic by design — bash 3.2 portability ruled out a JSON parser, and a flat file is trivially hand-editable or generable from any threat-intel feed. The *collector* (this script, stable) / *threat-intel* (the catalog, versioned independently) split is borrowed from [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee).

### AI agent review

The audit is intentionally under-opinionated: it emits raw, stable signals and leaves the synthesis — which findings matter for *this user's* threat model, which combinations of low-signal SKIPs add up to a real gap — to whoever reads the report. Increasingly that reader is an LLM. Point any AI coding agent at [docs/AGENTS.md](docs/AGENTS.md) (or a saved JSON) and it can produce contextual recommendations rather than a generic checklist — backup-desert detection, wallet-without-isolation, plaintext-disk-on-theft, SSH risk surface, and more.

### Sample output

```
macOS Posture Audit
Read-only. No changes will be made.
Host: MacBook-Pro.local · macOS 26.4.1 · arch arm64

━━━ 01 · System Integrity (Disk & Boot) ━━━
  ✅ PASS SIP (System Integrity Protection) is enabled
  ✅ PASS Gatekeeper is enabled
  ✅ PASS FileVault is on (full-disk encryption active)
  ✅ PASS Apple Silicon Secure Boot: Full Security
  ✅ PASS Third-party kernel extensions disabled

[…27 more sections…]

━━━ Summary ━━━
  ✅ Pass:  47
  ⚠️  Warn:  6
  ❌ Fail:  0
  ⏭  Skip:  10
```

## Safety & privacy

- **Read-only by default.** The only audit-script write is the explicit `--snapshot` report. The tripwire (`scripts/check-read-only.sh`) blocks command-position `rm`/`mv`/`cp`/`chmod`/`chown`/`defaults write`/`plutil -replace`/mutating `launchctl`, package installs (brew/npm/yarn/pnpm/pip/cargo/gem), `kill`, disk tooling, and `curl|bash` patterns, plus any network call outside `--network`. Two narrow allowlists — `sqlite3 -readonly -init /dev/null` (TCC.db before macOS 27, §22) and read-only-verb `osascript` (login items, §22) — each have positive/negative fixtures.
- **Offline by default.** `--network` is the only path to an external call (NextDNS routing, `gh auth status`).
- **Bash 3.2 compatible.** Works on stock macOS without `brew install bash`, and makes no assumptions about your folder layout, email, or installed apps.
- **Output is sensitive.** It maps which credential files live in `$HOME`, which TCC services have approved clients, which agents are installed, and which VPN/AV/wallet apps run — reading it tells someone what to attack. Use `--redact` before sharing; it masks hostnames, emails, usernames, IPs, `$HOME` paths, and brand names, and the credential check only ever prints filenames (`grep -l`). CI tests known redaction cases ([tests/integration/redaction.bats](tests/integration/redaction.bats)).

For a one-line skim, this should only surface read-only probes, hint text, or the opt-in network checks:

```bash
grep -En 'sudo|curl|gh |rm |mv |cp |chmod|chown|defaults|plutil|launchctl|kill|brew |npm |pip |osascript|sqlite3|diskutil|hdiutil' mac-posture-audit.sh
```

## Testing

```bash
brew install bats-core shellcheck shfmt

PATH="/usr/bin:$PATH" ./scripts/test.sh --check-tools
PATH="/usr/bin:$PATH" ./scripts/test.sh
```

The test runner checks syntax, ShellCheck, formatting, safety-checker fixtures, Bats tests, and Python tests. It gives Bats a temporary home directory. Section tests use fixtures. Some integration tests run real, read-only macOS probes in `--quick` mode; they check report structure, redaction, arguments, and counters.

On macOS, use Apple's `/usr/bin/python3` from Xcode or Command Line Tools.
The macOS 27.0.1 validation used its Python 3.9.6; the macOS CI jobs also select
`/usr/bin/python3` and record its version. A separate Python installation is not
needed. The optional renderer and tests require Python 3.9 or later. The Linux
fuzzing container has its own pinned runtime. On Apple silicon, use arm64 or
universal test tools. `--check-tools` checks whether each required tool can run before any
tests start. If a working version is already installed, put its directory first
in `PATH`. See the [macOS 27 notes](docs/macOS-27.md) for Rosetta limits.

## Compatibility

"Tested" means an actual run against the listed environment; "supported" means the script should work and degrade to `skip` for any check that doesn't apply.

| Type | Environment |
|---|---|
| Local automated tests and host smoke | macOS 27.0.1 (build 26A434), arm64, Bash 3.2.57. Section fixtures and real read-only `--quick` integration probes ran on this host; this is not full privileged validation. |
| Earlier manual full run | macOS 26.5 (Tahoe), arm64, Bash 3.2.57 |
| CI | GitHub Actions `macos-latest` — the exact `sw_vers` / `uname -m` / Bash version per release is printed in the Safety workflow's "Print runtime versions" step. |
| Expected compatible | macOS Sequoia (15), Sonoma (14), Ventura (13). Older releases may use legacy `defaults` formats that some checks skip on cleanly. |
| Architecture | Apple silicon for macOS 27. Intel support applies to compatible earlier macOS releases; Apple-silicon boot-security checks are not applicable on Intel. |

On macOS 27+, direct TCC database checks report `skip` with manual review
guidance. Background Security Improvements and Apple Intelligence settings also
need explicit review. See [macOS 27 coverage and test limits](docs/macOS-27.md)
for the verified platform changes, Apple sources, and the scope of local tests.

## What this isn't

- Not a remediation tool — it reports what's wrong; it doesn't fix anything.
- Not a malware scanner — use Bitdefender, Malwarebytes, or Objective-See for that.
- Not a substitute for a real security audit — it's a self-check you can run weekly to track posture.

## Roadmap

v1.x is the public-release line. Possible directions:

- **Evidence fields** in JSON rows so consumers get structured detail without scraping labels. *(Started in v1.7.0 — an optional, redaction-safe `evidence` object on a representative subset of checks; see [docs/schema.md → Evidence](docs/schema.md#evidence-added-v170). More checks to follow.)*
- **`--deep` mode** — slower, opt-in scan across project directories with explicit excludes and redaction-safe output.
- **Continuous snapshot mode** that stores JSON locally and alerts on newly-introduced failures.
- **Per-brand killswitch verification** for ProtonVPN / NordVPN (currently advisory) and broader messaging-app coverage (Signal, Discord, WhatsApp).

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the four invariants: read-only probes, bash 3.2 compatibility, stable IDs, and hermetic tests via `*_ROOTS` overrides.

For faster local validation, install GNU parallel and run
`PATH="/usr/bin:$PATH" BATS_JOBS=4 ./scripts/test.sh`. The default is one worker. CI uses four workers
and cancels superseded runs for the same branch; every PR and main push still
receives validation.

## License

MIT — see [LICENSE](./LICENSE).

# mac-posture-audit

[![Safety](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml/badge.svg?branch=main)](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Bash 3.2 compatible](https://img.shields.io/badge/bash-3.2%20compatible-blue)](#compatibility)

A read-only, single-file shell script that audits a macOS machine's security posture and prints a colored report. Runs in seconds, makes no changes, and needs nothing beyond what ships with macOS.

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

The tripwire is itself regression-tested (`tests/check-read-only/should_{pass,fail}/`), so the safety check has teeth. Tags and commits are SSH-signed; `git tag -v` only means something once you've trusted the signer's key out-of-band (GitHub publishes pubkeys at `/<user>.keys`). See [SECURITY.md](./SECURITY.md) for the full read-only guarantee and the narrow `sqlite3 -readonly` / read-only-verb `osascript` exceptions.

## What it checks

30 sections, 183 checks, by theme:

- **System integrity** — SIP, Gatekeeper, FileVault, Apple Silicon Secure Boot, third-party kernel extensions.
- **Login & privacy** — auto-login, screen-lock delay, Touch ID for sudo, Apple ads/analytics, Lockdown Mode.
- **Network** — firewall & stealth, sharing services, AirDrop/Bluetooth/Wi-Fi exposure, DNS/DoH & VPN (incl. killswitch), proxies/PAC/WPAD, `/etc/hosts`, 16 AV/EDR engines, outbound monitors (Little Snitch / LuLu).
- **Browsers & extensions** — installed/default browser, bundle-version staleness, profile counts, plus a Chromium/Safari/Firefox extension inventory that flags protective, wallet, and transaction-simulator add-ons.
- **Developer & supply chain** — npm/yarn/pnpm `ignore-scripts`, supply-chain scanners, `.npmrc` and registry rewrites, `gh` / git credential helpers, `extra-index-url` dependency-confusion risk, Homebrew taps, IDE workspace trust + folder-open task autorun + trusted-folder sprawl, plaintext registry tokens on disk (npm/PyPI/cargo/gem), and a `supply.blast_radius` composite that answers "if a malicious dependency install runs code here, how far can it reach?"
- **Credentials & secrets** — credential patterns in shell rc files, `.env` and sensitive dotfiles, SSH key encryption + agent, git signing.
- **Crypto & 2FA** — hardware wallets (Ledger / Trezor / Keystone / GridPlus), password managers, YubiKey / FIDO2, and a wallet-isolation composite.
- **Backups & cloud** — Time Machine destinations / recency / encryption, third-party backup tools, iCloud sync, and sensitive data (`.ssh` / `.aws` / wallets) leaking into cloud-sync roots.
- **Persistence & access** — LaunchAgents/Daemons (incl. webhook/exfil-shaped destinations), login items, crontab, TCC permission holders, remote-access apps, sandboxes, MDM enrollment, clipboard managers.
- **Agents & MCP** — MCP servers (Cursor / Claude / Windsurf / Gemini): server count, `@latest`/`:latest` unpinned launchers, remote HTTP/SSE transports, dynamic launchers (npx/uvx/bunx/pipx/docker), filesystem-capable servers, and webhook/exfil destinations. MCP env values and key names are never read.
- **AI agent instruction hygiene** — discovers the files that steer coding agents (`AGENTS.md` / `CLAUDE.md` / `GEMINI.md` / `.cursorrules` / `.cursor` rules, etc.) under your project roots and flags hidden/zero-width Unicode, suspicious directive-shaped phrases (prompt-injection / pipe-to-shell), and webhook destinations. Two-tier discovery with strict bounds (depth 3, ≤256 KB/file, ≤200 files, junk dirs pruned); matched lines, URLs, and tokens are never printed.
- **Webhook / exfil shapes** — one-line exfil endpoints (Discord/Slack/Telegram/webhook.site/RequestBin/Pipedream/IFTTT/Zapier) detected across config surfaces that run automatically — shell rc, LaunchAgents, MCP configs, agent instruction files, `~/.npmrc` / `~/.pypirc` — aggregated into `config.webhook_exfil_shape`. Provider name only; never the URL or token.
- **Inventory (catalog-driven)** — browser extensions, editor extensions (VS Code / Cursor / Windsurf / VSCodium), and MCP server IDs, each matchable against an exposure catalog of known-bad IDs.
- **Attack chains** — named cross-section composites that fire only when a full attack path is assembled: `chain.fake_interview` (IDE auto-runs untrusted code + no sandbox), `chain.wallet_drain` (wallet + no isolation + no outbound monitor), `chain.agent_exposure` (a filesystem/remote MCP agent on the same machine as a wallet), `chain.cloud_exfil` (SSH keys / wallet data / dotfiles under a cloud-sync root), `chain.supply_to_wallet` (a poisoned dependency install reaching an unisolated wallet), `chain.agent_supply_chain` (an agent/IDE/MCP surface that can reach registry tokens, SSH keys, or a wallet).

Several checks are composites that fold multiple rows into a single verdict (`system.theft_resistance`, `backup.recovery_path`, `ssh.posture`, `users.crypto_isolation_indicator`, the `chain.*` attack chains, …). The canonical check list is [tests/fixtures/expected_ids.txt](tests/fixtures/expected_ids.txt); composite patterns and agent-review guidance live in [docs/AGENTS.md](docs/AGENTS.md).

Every run ends with an **Executive Verdict** — a profile-aware one-line read plus an `Action priority:` level — and a **Top risks to address** list that ranks the findings that actually matter for your threat model (`urgent` > `high` > `medium` > `low`) instead of dumping them in scan order. Both appear in the JSON too (`executive_verdict`, ranked `top_risks`). See [Top risks & verdict](#top-risks--verdict).

## Usage

```bash
./mac-posture-audit.sh                                        # default: offline, read-only
sudo ./mac-posture-audit.sh                                   # fuller audit; privileged probes skip without sudo
./mac-posture-audit.sh --network                              # opt-in live checks (NextDNS routing, gh auth)
./mac-posture-audit.sh --json --quick --redact > posture.json # shareable machine-readable report
```

`--quick` skips privileged checks; `sudo` unlocks Secure Boot details, Remote Login, TCC permission holders, and sudoers. The default run is offline — `--network` is the only path to an external call.

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
| `--top N` | Cap the "Top risks to address" list to N items (default 7). `--top 0` hides the list but keeps the Executive Verdict. |
| `--explain ID` | Print the threat rationale + per-profile severity for one check id (e.g. `chain.fake_interview`) and exit, without scanning. |
| `--report md` | Render a shareable Markdown report (Executive Verdict + Top risks + full results table) instead of the terminal report. Honors `--redact`. |
| `--snapshot` | Append a redacted JSON snapshot to `~/.mac-posture-audit/history/` (implies `--redact`). The only write the tool performs; default runs are read-only. |
| `--trend` | Read-only: summarize how posture changed across stored snapshots (oldest vs newest). |
| `--selftest` | Run a hermetic end-to-end smoke test and exit. Non-zero = the install can no longer detect what it should. |
| `--version` / `--help` | Show version / usage and exit |

Exit code: `0` if no failures, `1` if any check fails, `2` if the script itself errors.

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
  "summary":{"pass":47,"warn":6,"fail":0,"skip":10,"total":63},
  "executive_verdict":{"profile":"founder","tier":"high","text":"…","top_counts":{"urgent":0,"high":4,"medium":2,"low":1}},
  "top_risks":[
    {"rank":1,"id":"ext.wallet","status":"warn","tier":"high","label":"Wallet extension(s) installed: …","hint":"…"}
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
./mac-posture-audit.sh --report md > posture.md            # shareable Markdown (honors --redact)
./mac-posture-audit.sh --json --redact | python3 tools/render_report.py > report.html   # self-contained HTML, no deps
./mac-posture-audit.sh --snapshot                          # append a redacted JSON to ~/.mac-posture-audit/history/
./mac-posture-audit.sh --trend                             # summarize improved/regressed checks across snapshots
```

`--snapshot` is the **only** write the tool ever performs (to its own data dir, redaction forced); everything else stays read-only. `tools/render_report.py` is a stdlib-only Python companion so the core stays a single shell file. For a maintained deny-list, point `--exposure-catalog` at [`catalog/known-bad.txt`](catalog/known-bad.txt) and refresh it via `git pull`.

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

- **Read-only.** Never modifies any file or setting. The tripwire (`scripts/check-read-only.sh`) blocks command-position `rm`/`mv`/`cp`/`chmod`/`chown`/`defaults write`/`plutil -replace`/mutating `launchctl`, package installs (brew/npm/yarn/pnpm/pip/cargo/gem), `kill`, disk tooling, and `curl|bash` patterns, plus any network call outside `--network`. Two narrow allowlists — `sqlite3 -readonly` (TCC.db, §22) and read-only-verb `osascript` (login items, §22) — each have positive/negative fixtures.
- **Offline by default.** `--network` is the only path to an external call (NextDNS routing, `gh auth status`).
- **Bash 3.2 compatible.** Works on stock macOS without `brew install bash`, and makes no assumptions about your folder layout, email, or installed apps.
- **Output is sensitive.** It maps which credential files live in `$HOME`, which TCC services have approved clients, which agents are installed, and which VPN/AV/wallet apps run — reading it tells someone what to attack. Use `--redact` before sharing; it masks hostnames, emails, usernames, IPs, `$HOME` paths, and brand names, and the credential check only ever prints filenames (`grep -l`). Redaction is asserted leak-free on every CI build ([tests/integration/redaction.bats](tests/integration/redaction.bats)).

For a one-line skim, this should only surface read-only probes, hint text, or the opt-in network checks:

```bash
grep -En 'sudo|curl|gh |rm |mv |cp |chmod|chown|defaults|plutil|launchctl|kill|brew |npm |pip |osascript|sqlite3|diskutil|hdiutil' mac-posture-audit.sh
```

## Testing

```bash
brew install bats-core shellcheck shfmt

bash -n mac-posture-audit.sh
shellcheck -S warning mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
shfmt -d -i 2 mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
./scripts/check-read-only.sh
bats tests/sections tests/integration
```

The Bats suite sources the script as a library with fixtures/mocked macOS CLIs for section-level tests; integration tests run the real script in `--quick` mode and assert JSON validity, redaction, argument handling, and summary-counter parity.

## Compatibility

"Tested" means an actual run against the listed environment; "supported" means the script should work and degrade to `skip` for any check that doesn't apply.

| Type | Environment |
|---|---|
| Manual full run | macOS 26.5 (Tahoe), arm64, Bash 3.2.57 |
| CI | GitHub Actions `macos-latest` — the exact `sw_vers` / `uname -m` / Bash version per release is printed in the Safety workflow's "Print runtime versions" step. |
| Expected compatible | macOS Sequoia (15), Sonoma (14), Ventura (13). Older releases may use legacy `defaults` formats that some checks skip on cleanly. |
| Architecture | Apple Silicon (primary, manually tested); Intel supported, with Apple-Silicon boot-security checks becoming n/a. |

## What this isn't

- Not a remediation tool — it reports what's wrong; it doesn't fix anything.
- Not a malware scanner — use Bitdefender, Malwarebytes, or Objective-See for that.
- Not a substitute for a real security audit — it's a self-check you can run weekly to track posture.

## Roadmap

v1.x is the public-release line. Possible directions:

- **Evidence fields** in JSON rows so consumers get structured detail without scraping labels.
- **`--deep` mode** — slower, opt-in scan across project directories with explicit excludes and redaction-safe output.
- **Signed release artifacts** with published checksums.
- **Continuous snapshot mode** that stores JSON locally and alerts on newly-introduced failures.
- **Per-brand killswitch verification** for ProtonVPN / NordVPN (currently advisory) and broader messaging-app coverage (Signal, Discord, WhatsApp).

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the four invariants: read-only probes, bash 3.2 compatibility, stable IDs, and hermetic tests via `*_ROOTS` overrides.

## License

MIT — see [LICENSE](./LICENSE).

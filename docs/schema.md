# JSON output schema

`mac-posture-audit.sh --json` emits a single JSON object with the structure below. The shape is stable across runs and across versions; additions are non-breaking, renames bump the major version.

```jsonc
{
  "host": "string",         // hostname or "<HOST>" if --redact
  "macos": "string",        // sw_vers -productVersion, e.g. "26.4.1"
  "arch": "string",         // uname -m, e.g. "arm64" or "x86_64"
  "summary": {
    "pass": 0,              // non-negative int; pass+warn+fail+skip == len(results)
    "warn": 0,
    "fail": 0,
    "skip": 0,
    "total": 0             // added v1.3.0; equals len(results)
  },
  "executive_verdict": {    // added v1.3.0 — profile-aware decision summary
    "profile": "string",   // active --profile
    "tier":    "urgent|high|medium|low|none",  // action priority (highest tier present)
    "text":    "string",   // one-line human verdict
    "top_counts": { "urgent": 0, "high": 0, "medium": 0, "low": 0 }
  },
  "top_risks": [            // added v1.3.0 — warn/fail rows ranked by action priority
    {
      "rank":   0,          // 1-based, contiguous, urgent→high→medium→low
      "id":     "string",
      "status": "warn|fail",
      "tier":   "urgent|high|medium|low",
      "effort": "low|medium|high",  // added v1.5.0 — remediation effort
      "label":  "string",
      "hint":   "string"
    }
  ],
  "results": [
    {
      "id":     "string",   // stable id, unique within a single run
      "status": "pass|warn|fail|skip",
      "label":  "string",   // human-readable summary
      "hint":   "string",   // remediation pointer; may be empty
      "evidence": {          // OPTIONAL, added v1.7.0 — see "Evidence" below.
        "…": "scalar"       // present only on checks that stage it; flat
      }                      //   object of strings / integers / booleans.
    }
  ]
}
```

## Field rules

- **`summary.{pass,warn,fail,skip}`** — non-negative integers. Their sum **must** equal `len(results)`. The CI smoke test asserts this on every push.
- **`results[].id`** — non-empty string, unique within the array. Same logical check always uses the same id across runs, which is what makes `--diff` work.
- **`results[].status`** — one of the four enum values. Profiles (see `--profile`) can rewrite a status from one enum value to another (e.g. `warn → fail` under `web3` for `ext.wallet`); they cannot introduce new statuses.
- **`results[].label`** — opaque to consumers. Only `id` is stable; `label` may be reworded between versions.
- **`results[].hint`** — may be empty (`""`) for `pass` and uninformative `skip` rows.
- **`results[].evidence`** *(added v1.7.0)* — an **optional** object carrying the machine-checked facts the row's status was derived from. **Absent** on most rows; present only on checks that stage it (a growing subset — see the [Evidence](#evidence-added-v170) section). A flat object of scalar values (string / integer / boolean); no nested objects or arrays, so the stock-shell `--diff` parser is never confused. Values are redaction-safe by construction (counts, booleans, fixed enums) and are emitted regardless of `--redact`. Additive and non-breaking: a consumer that ignores `evidence` sees exactly the pre-v1.7 row.
- **`summary.total`** *(added v1.3.0)* — equals `len(results)` and the sum of the four counters.
- **`executive_verdict`** *(added v1.3.0)* — `tier` is the action-priority level (the highest tier present in `top_risks`, or `none` when there are no warn/fail rows). `text` is opaque human prose (reworded freely across versions). `top_counts` sums the ranked tiers.
- **`top_risks`** *(added v1.3.0)* — the warn/fail rows ranked by action priority; `rank` is 1-based and contiguous, ordered urgent→high→medium→low. Capped by `--top N` (default 7); `--top 0` yields `[]`. `pass`/`skip` rows never appear. Always an array, never absent. Each entry carries an **`effort`** *(added v1.5.0)* hint (`low`/`medium`/`high`) for impact-per-effort triage.

## Evidence *(added v1.7.0)*

Some rows carry an optional `evidence` object: the small set of facts the status was computed from, so a consumer (increasingly an LLM — see [AGENTS.md](AGENTS.md)) can act on structured data instead of scraping the prose `label`. This is the roadmap's "evidence fields" item — the thing that makes "point an AI agent at the JSON" produce good synthesis rather than label-matching.

Design rules:

- **Optional and additive.** Absent on rows that don't stage it. Consumers must treat a missing `evidence` as "no structured detail available," never as an error.
- **Flat scalars only.** Each value is a JSON string, integer, or boolean. No nested objects or arrays — this keeps the stock-shell `--diff` and `--trend` parsers (which split rows on `},{`) correct.
- **Redaction-safe by construction.** Evidence holds counts, booleans, and fixed enums — never hostnames, brands, paths, or usernames — so it is emitted the same with or without `--redact`.
- **`id` remains the contract.** Evidence keys for a given `id` are stable within a major version but, like `label`, are additive: new keys may appear. Don't hard-fail on an unexpected key.

Checks that emit evidence today (the representative first set; more will follow):

| id | evidence keys |
|---|---|
| `system.sip.enabled` | `probe` (string), `enabled` (bool) |
| `system.gatekeeper.enabled` | `probe` (string), `enabled` (bool) |
| `system.filevault.on` | `probe` (string), `state` (`on`/`off`/`unknown`) |
| `ssh.posture` | `key_state` (`none`/`encrypted`/`unencrypted`/`unknown`), `external_agent` (bool) |
| `supply.posture` | `managers_running_scripts` (int 0–3), `scanner_present` (bool) |
| `backup.recovery_path` | `time_machine` (bool), `offsite` (bool), `icloud_drive` (bool) |

Example row:

```json
{
  "id": "ssh.posture",
  "status": "fail",
  "label": "SSH posture: unencrypted on-disk keys with no external agent",
  "hint": "Either add a passphrase … or move to an external SSH agent …",
  "evidence": { "key_state": "unencrypted", "external_agent": false }
}
```

## ID grammar

Two shapes:

- **Fixed**: `<area>.<subject>.<fact>` — a logical check that emits one row whose status varies. Example: `system.sip.enabled` (always one row, status `pass` or `fail`).
- **Templated**: `<area>.<subject>.<instance>` — checks where one row is emitted per detected item. The `<instance>` segment is the lower-cased item name with `[^a-z0-9_]` collapsed to `_`. Example: `network.sharing.screensharing`, `network.sharing.smbd`, `persist.system.launchagents`.

Canonical lists:

- Fixed ids: [`tests/fixtures/expected_ids.txt`](../tests/fixtures/expected_ids.txt)
- Templated id patterns (regexes): [`tests/fixtures/expected_id_patterns.txt`](../tests/fixtures/expected_id_patterns.txt)

CI fails any run that emits an id not on either list.

## Versioning

- **Adding a new id** — non-breaking, additive.
- **Adding a new top-level field** — non-breaking, additive.
- **Renaming an id, changing the meaning of an existing id, or removing a field** — breaking, requires a major version bump.

## Diffing two runs

`mac-posture-audit.sh --diff <previous.json>` prints rows where `status` differs between the previous JSON file and the current run. Output is one row per change with the status flip:

```
ext.wallet                  warn → fail
network.bluetooth.off       pass → warn
ssh.keys.unencrypted        warn → pass   (resolved)
+ persist.user.launchagents pass          (new check)
- av.engine.detected                       (removed in current run)
```

Exit code: `0` if no diffs, `1` if any diff, `2` on error (file missing, parse error). Pair with `--json --quick --redact > yesterday.json && ./mac-posture-audit.sh --diff yesterday.json` to track posture over time.

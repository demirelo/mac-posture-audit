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
      "hint":   "string"    // remediation pointer; may be empty
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
- **`summary.total`** *(added v1.3.0)* — equals `len(results)` and the sum of the four counters.
- **`executive_verdict`** *(added v1.3.0)* — `tier` is the action-priority level (the highest tier present in `top_risks`, or `none` when there are no warn/fail rows). `text` is opaque human prose (reworded freely across versions). `top_counts` sums the ranked tiers.
- **`top_risks`** *(added v1.3.0)* — the warn/fail rows ranked by action priority; `rank` is 1-based and contiguous, ordered urgent→high→medium→low. Capped by `--top N` (default 7); `--top 0` yields `[]`. `pass`/`skip` rows never appear. Always an array, never absent. Each entry carries an **`effort`** *(added v1.5.0)* hint (`low`/`medium`/`high`) for impact-per-effort triage.

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

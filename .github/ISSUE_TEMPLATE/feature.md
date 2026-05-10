---
name: Feature / new check
about: Propose a new check, a composite, a profile override, or a CLI flag
title: ''
labels: enhancement
assignees: ''
---

## What threat or posture gap does this address?

<!-- The audit is intentionally conservative about adding noise. Lead with the
     threat model the new check / behaviour catches. Cite a real incident,
     a CVE class, or a documented attacker pattern where possible. -->

## Why are existing rows insufficient?

<!-- Skim tests/fixtures/expected_ids.txt and tests/fixtures/expected_id_patterns.txt
     first. Many checks people propose are already there. -->

## Proposed check

- Proposed ID (follow `<area>.<subject>.<fact>` grammar):
- Section it belongs to (or "new section N · <name>"):
- pass / warn / fail / skip defaults:
- Which `--profile`(s) should escalate it, if any:
- Composite or atomic? If composite, which constituent IDs does it read?

## Cost

- Default-mode, `--network`-only, or `--deep`-only? (`--deep` doesn't exist yet; mark this if your check would justify adding it.)
- Sudo required?
- Approximate runtime on a stock macOS host:
- New CLI dependency? (Stock macOS tools only — see CONTRIBUTING.md.)

## Privacy

<!-- Does the check's label embed identifying values (paths, bundle IDs, brand
     names, app inventory)? If so, how does the row look under `--redact`?
     The `tests/integration/redaction.bats` suite will assert absence of
     known leak tokens. -->

## Alternatives considered

<!-- e.g. "I considered a composite of existing rows X + Y + Z, but the
     audit can't tell from the rows alone whether <condition> applies." -->

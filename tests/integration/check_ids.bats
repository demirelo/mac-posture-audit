#!/usr/bin/env bats

# Validates that every emitted check id is recognised, unique within a single
# run, and that every fixed id in expected_ids.txt has at least one matching
# emitter in the source. Catches typos in either direction.

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  export REPO_ROOT
}

@test "every emitted id is non-empty, unique, and either listed or matches a pattern" {
  cd "$REPO_ROOT"
  ./mac-posture-audit.sh --json --quick --redact >"$BATS_TEST_TMPDIR/posture.json" || true
  python3 - "$BATS_TEST_TMPDIR/posture.json" <<'PY'
import json, re, sys
from pathlib import Path

repo = Path(sys.argv[1]).parent.parent
posture_path = sys.argv[1]
d = json.load(open(posture_path))
ids = [r["id"] for r in d["results"]]

assert all(ids), "every row must have a non-empty id; found empty"
dupes = sorted({i for i in ids if ids.count(i) > 1})
assert not dupes, f"duplicate ids in a single run: {dupes}"

fixed = set(Path("tests/fixtures/expected_ids.txt").read_text().split())
patterns = [
    re.compile(line)
    for line in Path("tests/fixtures/expected_id_patterns.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]
unknown = [
    i for i in ids
    if i not in fixed and not any(p.match(i) for p in patterns)
]
assert not unknown, f"emitted ids not in fixed list nor matching any pattern: {unknown}"
print(f"ok: {len(ids)} unique ids, all recognised")
PY
}

@test "every fixed id in expected_ids.txt has at least one emitter in the source" {
  cd "$REPO_ROOT"
  python3 - <<'PY'
from pathlib import Path

src = Path("mac-posture-audit.sh").read_text()
fixed = Path("tests/fixtures/expected_ids.txt").read_text().split()
# Some IDs are emitted via templates (e.g. persist.system.${kind_name},
# supply.cargo.creds via a "$path|$id|$name" spec loop). Check for the bare
# id substring so both quoted and templated forms are recognised.
unreached = [i for i in fixed if i not in src]
assert not unreached, f"fixed ids in expected_ids.txt with no emitter in source: {unreached}"
print(f"ok: all {len(fixed)} fixed ids have emitters")
PY
}

@test "every PROFILE_OVERRIDES entry references a recognised id" {
  cd "$REPO_ROOT"
  python3 - <<'PY'
import re
from pathlib import Path

src = Path("mac-posture-audit.sh").read_text()
m = re.search(r"PROFILE_OVERRIDES=\(([\s\S]*?)\n\)", src)
assert m, "PROFILE_OVERRIDES table not found in source"
entries = re.findall(r'"([^"]+)"', m.group(1))
override_ids = sorted({e.split("|")[1] for e in entries})

fixed = set(Path("tests/fixtures/expected_ids.txt").read_text().split())
patterns = [
    re.compile(line)
    for line in Path("tests/fixtures/expected_id_patterns.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]
unknown = [
    i for i in override_ids
    if i not in fixed and not any(p.match(i) for p in patterns)
]
assert not unknown, f"PROFILE_OVERRIDES references ids not in fixed list nor any pattern: {unknown}"
print(f"ok: all {len(override_ids)} override ids are recognised")
PY
}

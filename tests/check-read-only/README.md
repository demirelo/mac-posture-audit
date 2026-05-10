# Tripwire negative tests

The scripts in this directory are **inputs to** `scripts/check-read-only.sh`,
not scripts you run. They exist so CI can prove the tripwire still rejects
mutating command patterns.

- `should_pass/clean.sh` — must be accepted by the tripwire.
- `should_fail/*.sh` — each must be **rejected** by the tripwire. A failure here
  means the tripwire has lost a rule and the safety story has weakened.

The CI workflow runs the tripwire against every fixture and fails if a
`should_fail/*.sh` is ever accepted. The fixtures themselves are not executed —
they are only inspected as text — so the destructive-looking lines inside them
never run. As a defence-in-depth measure each fixture starts with `exit 0` so
even an accidental `bash fixture.sh` would short-circuit before reaching the
mutating command.

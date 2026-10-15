# Safety checker regression tests

Run `./scripts/test.sh` from the repository root. The script runs static checks,
the safety fixtures, Bats tests, renderer unit tests, and release-input tests.
Integration smoke tests run read-only `--quick` audits. The runner gives Bats
an empty temporary home directory, but system settings and applications remain
visible. The complete suite is not hermetic.

`should_pass/*.sh` and `should_fail/*` are input files for
`scripts/check-read-only.sh`. The runner only reads them as text. It must accept
every positive fixture and reject every negative fixture. Negative fixtures have
no `.sh` extension, so unrelated supply-chain scanners do not treat intentional
unsafe examples as executable project code. New fixtures include `exit 0` as an
additional precaution. Never execute a fixture.

The fixtures cover mutating commands, common wrappers and absolute paths,
commands after an allowed invocation, command substitutions in report labels,
SQLite CLI side effects, exact network arguments, and the true arm of the local
`NETWORK` guard. Allowed network commands must occur inside a separate
`if $NETWORK; then` block. A comment or unrelated block cannot enable them.

The checker is a static tripwire. It is not a shell interpreter or a security
boundary against arbitrary obfuscated code. Review dynamic command construction,
redirections, embedded programs, sourced files, and explicit snapshot writes.
The ordinary audit is read-only; `--snapshot` is an explicit local-write option
with separate runtime checks and tests.

`test_release_workflow.py` runs the actual release-tag validation against valid
versions and hostile input. It also checks that publishing uses the tested
commit and does not replace existing release assets.

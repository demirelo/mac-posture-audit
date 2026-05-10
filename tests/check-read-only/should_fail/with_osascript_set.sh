#!/usr/bin/env bash
exit 0
# Tripwire bait below; never executed. osascript with a mutating verb
# (set / do shell script) must be rejected even though plain `osascript`
# is allowlisted for read-only `to get` queries.
osascript -e 'tell application "System Events" to set name of first login item to "x"'

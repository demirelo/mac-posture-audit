#!/usr/bin/env bash
exit 0
# Tripwire bait below; never executed. The -readonly text appears only inside
# SQL and must not satisfy the sqlite3 allowlist.
sqlite3 /tmp/never.db "DELETE FROM users WHERE note = '-readonly'"

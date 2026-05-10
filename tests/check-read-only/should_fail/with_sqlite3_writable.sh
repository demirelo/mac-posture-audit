#!/usr/bin/env bash
exit 0
# Tripwire bait below; never executed.
sqlite3 /tmp/never.db "DELETE FROM users"

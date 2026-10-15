#!/usr/bin/env bash
# Tripwire input only.
exit 0
sqlite3 -readonly -init /dev/null /tmp/never.db "SELECT 1"; sqlite3 -readonly -init /dev/null /tmp/never.db "SELECT 2"

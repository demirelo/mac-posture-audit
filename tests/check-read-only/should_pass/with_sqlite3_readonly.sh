#!/usr/bin/env bash
# A read-only sqlite3 invocation must be accepted by the tripwire because
# Section 22 (Persistence & TCC) inspects /Library/Application Support/
# com.apple.TCC/TCC.db this way.
exit 0

sudo -n sqlite3 -readonly /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service FROM access WHERE auth_value=2"

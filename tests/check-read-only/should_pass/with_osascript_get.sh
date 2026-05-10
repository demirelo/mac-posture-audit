#!/usr/bin/env bash
# A read-only osascript query must be accepted by the tripwire because
# Section 22 enumerates login items this way.
exit 0

osascript -e 'tell application "System Events" to get the name of every login item'

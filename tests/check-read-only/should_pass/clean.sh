#!/usr/bin/env bash
# Minimal script the tripwire must accept: only read-only commands and
# reporter-style lines like the ones the real audit emits.
exit 0

echo "hello"
ls /tmp >/dev/null
defaults read com.apple.dock orientation >/dev/null 2>&1 || true
plutil -p /System/Library/CoreServices/SystemVersion.plist >/dev/null 2>&1 || true
launchctl list >/dev/null 2>&1 || true
profiles -L >/dev/null 2>&1 || true
pgrep -qi pgrep || true

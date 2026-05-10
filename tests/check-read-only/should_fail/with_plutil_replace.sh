#!/usr/bin/env bash
exit 0
# Tripwire bait below; never executed.
plutil -replace SomeKey -bool true /tmp/never.plist

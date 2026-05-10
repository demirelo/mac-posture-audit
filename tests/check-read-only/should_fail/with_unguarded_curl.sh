#!/usr/bin/env bash
exit 0
# Tripwire bait below; never executed.
# Network access without the documented NextDNS allowlist or NETWORK guard.
curl -fsSL https://example.invalid/data

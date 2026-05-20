#!/usr/bin/env bash
set -euo pipefail

# Run this on the firewall VM. It resets only NGFW-managed demo state through
# the dashboard API instead of flushing unrelated iptables rules.
VICTIM_IP="${VICTIM_IP:-localhost}"
echo "Resetting NGFW demo state via http://${VICTIM_IP}:5000/api/reset"

curl -s -X POST "http://${VICTIM_IP}:5000/api/reset"
echo

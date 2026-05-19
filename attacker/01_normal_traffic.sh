#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${VICTIM_IP:-192.168.56.10}"
echo "Target firewall VM: ${VICTIM_IP} (override with VICTIM_IP=<ip>)"

curl -s -o /dev/null "http://${VICTIM_IP}/" || true

if command -v sshpass >/dev/null 2>&1; then
  sshpass -p password123 ssh -o StrictHostKeyChecking=no testuser@"${VICTIM_IP}" "echo hello" || true
else
  echo "sshpass is missing; skipping SSH normal-traffic sample."
fi

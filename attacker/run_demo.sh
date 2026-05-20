#!/usr/bin/env bash
set -euo pipefail

: "${VICTIM_IP:?Set VICTIM_IP first}"
HERE="$(cd "$(dirname "$0")" && pwd)"

pause() { read -r -p "[Press Enter for next scene] " _; }

echo "=== Scene 1: Normal traffic ==="; bash "$HERE/01_normal_traffic.sh"; pause
echo "=== Scene 2: Port scan ==="; bash "$HERE/02_port_scan.sh"; pause
echo "=== Scene 3: SSH brute force ==="; bash "$HERE/03_brute_force.sh"; pause
echo "=== Scene 4: DoS (rate-limited SYN) ==="; bash "$HERE/04_dos_synflood.sh"; pause
echo "Demo complete."

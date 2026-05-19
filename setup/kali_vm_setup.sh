#!/usr/bin/env bash
set -euo pipefail

# Spec: docs/specs/2026-05-13-ngfw-ml-design.md
# LAB-ONLY setup for the Mini NGFW Kali attacker VM.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script with sudo: sudo bash setup/kali_vm_setup.sh"
  exit 1
fi

WORDLIST="/usr/share/wordlists/rockyou.txt"
WORDLIST_GZ="${WORDLIST}.gz"

echo "[1/3] Installing attacker VM packages..."
apt update
apt install -y nmap hydra hping3 slowhttptest curl

echo "[2/3] Ensuring rockyou.txt exists..."
mkdir -p "$(dirname "${WORDLIST}")"
if [[ ! -f "${WORDLIST}" ]]; then
  if [[ -f "${WORDLIST_GZ}" ]]; then
    gunzip -k "${WORDLIST_GZ}"
  else
    cat > "${WORDLIST}" <<'EOF'
password
password123
123456
12345678
admin
qwerty
letmein
welcome
testuser
toor
EOF
  fi
fi

echo "[3/3] Final summary"
echo "Attacker VM IPs:"
ip -br addr
echo
echo "Available demo scripts: cd introProjesi && VICTIM_IP=<firewall-ip> bash attacker/run_demo.sh"
echo "Kali attacker VM setup complete."

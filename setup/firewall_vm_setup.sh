#!/usr/bin/env bash
set -euo pipefail

# Spec: docs/specs/2026-05-13-ngfw-ml-design.md
# INSECURE LAB-ONLY setup for the Mini NGFW firewall/victim VM.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script with sudo: sudo bash setup/firewall_vm_setup.sh"
  exit 1
fi

LAB_USER="testuser"
LAB_PASSWORD="password123"
SUDO_USER_NAME="${SUDO_USER:-${USER}}"

echo "[1/6] Installing firewall VM packages..."
apt update
apt install -y python3-pip python3-venv iptables tcpdump libpcap-dev openssh-server vsftpd libcap2-bin

echo "[2/6] Creating INSECURE LAB-ONLY user '${LAB_USER}'..."
if ! id "${LAB_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${LAB_USER}"
fi
echo "${LAB_USER}:${LAB_PASSWORD}" | chpasswd

echo "[3/6] Configuring SSH and vsftpd victim services..."
systemctl enable ssh
systemctl start ssh

if grep -q '^#\?local_enable=' /etc/vsftpd.conf; then
  sed -i 's/^#\?local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
else
  echo 'local_enable=YES' >> /etc/vsftpd.conf
fi

if grep -q '^#\?write_enable=' /etc/vsftpd.conf; then
  sed -i 's/^#\?write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
else
  echo 'write_enable=YES' >> /etc/vsftpd.conf
fi

systemctl enable vsftpd
systemctl restart vsftpd

echo "[4/6] Granting Python packet capture capabilities..."
PYTHON_BIN="$(readlink -f "$(command -v python3)")"
setcap cap_net_raw,cap_net_admin=eip "${PYTHON_BIN}"

echo "[5/6] Allowing '${SUDO_USER_NAME}' passwordless iptables for the demo..."
cat > /etc/sudoers.d/ngfw <<EOF
${SUDO_USER_NAME} ALL=(root) NOPASSWD: /usr/sbin/iptables
EOF
chmod 0440 /etc/sudoers.d/ngfw
visudo -cf /etc/sudoers.d/ngfw >/dev/null

echo "[6/6] Final summary"
echo "NICs:"
ip -br link
echo
echo "IPs:"
ip -br addr
echo
echo "Services:"
systemctl --no-pager --type=service --state=running status ssh vsftpd || true
echo
echo "Firewall VM setup complete. LAB-ONLY credentials: ${LAB_USER}/${LAB_PASSWORD}"

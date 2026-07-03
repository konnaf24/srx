#!/usr/bin/env bash
#
# setup_target.sh — provision the TARGET host so every probe workload completes.
#
# Brings up the server-side services the generators talk to:
#   nginx    :80   (serves an EICAR test file + index)
#   dnsmasq  :53   (DNS, bound to the host's public IP)
#   vsftpd   :21   (FTP banner for App-ID handshake)
#   iperf3   :5201 (throughput server)
#
# Verified against Ubuntu 24.04. Run on the target host you OWN / are
# AUTHORIZED to test (e.g. 84.254.1.45).
#
# Usage:
#     sudo BIND_IP=84.254.1.45 ./deploy/setup_target.sh
#
set -euo pipefail

# IP dnsmasq should listen on (must be the host's own public IP so it coexists
# with systemd-resolved, which stays on loopback).
BIND_IP="${BIND_IP:-$(hostname -I | awk '{print $1}')}"
echo "==> Target bind IP: $BIND_IP"

export DEBIAN_FRONTEND=noninteractive
echo "iperf3 iperf3/start_daemon boolean true"  | sudo debconf-set-selections
echo "iperf3 iperf3/autostart boolean true"     | sudo debconf-set-selections

echo "==> Installing nginx vsftpd iperf3 dnsmasq"
sudo apt-get update -q
sudo apt-get install -y -q nginx vsftpd iperf3 dnsmasq

echo "==> nginx: EICAR file + index"
# EICAR is the standard, harmless antivirus TEST string (never live malware).
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    | sudo tee /var/www/html/eicar.com >/dev/null
echo ok-eicar | sudo tee /var/www/html/index.html >/dev/null
sudo systemctl enable --now nginx
sudo systemctl restart nginx

echo "==> dnsmasq: listen on $BIND_IP (loopback resolver untouched)"
sudo mkdir -p /etc/dnsmasq.d
sudo tee /etc/dnsmasq.d/probe.conf >/dev/null <<CFG
listen-address=$BIND_IP
bind-interfaces
no-resolv
server=8.8.8.8
CFG
sudo systemctl enable --now dnsmasq
sudo systemctl restart dnsmasq

echo "==> vsftpd"
sudo systemctl enable --now vsftpd
sudo systemctl restart vsftpd

echo "==> iperf3 server (:5201)"
sudo systemctl enable --now iperf3 || true
sudo systemctl restart iperf3 || true

echo "==> Listening sockets (public):"
ss -tulnp | grep -E ":(21|53|80|5201) " | grep -vE "127.0.0.5[34]" || true

echo "==> ufw status:"
sudo ufw status 2>/dev/null | head -1 || echo "ufw not installed"

echo "Target host ready."

#!/usr/bin/env bash
#
# setup_generator.sh — provision the GENERATOR host for the SRX detection probe.
#
# Installs system binaries, clones/uses this repo, creates a Python venv,
# installs Python deps + Playwright (with Ubuntu 24.04 chromium runtime libs),
# and copies the example config. Verified against Ubuntu 24.04.
#
# Usage (run on the generator host, e.g. 84.254.1.46):
#     sudo ./deploy/setup_generator.sh
#
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/srx}"

echo "==> Installing system binaries (nmap hping3 wrk iperf3 tshark + python)"
export DEBIAN_FRONTEND=noninteractive
# Preseed so wireshark/tshark and iperf3 don't prompt.
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
echo "iperf3 iperf3/start_daemon boolean false" | sudo debconf-set-selections
sudo apt-get update -q
sudo apt-get install -y -q \
    nmap hping3 wrk iperf3 tshark \
    python3-venv python3-pip git

echo "==> Ensuring repo at $REPO_DIR"
if [ ! -d "$REPO_DIR/.git" ]; then
    git clone https://github.com/konnaf24/srx "$REPO_DIR"
fi
cd "$REPO_DIR"

echo "==> Creating venv + installing Python deps"
python3 -m venv venv
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q -r requirements.txt

echo "==> Installing Playwright chromium runtime libs (Ubuntu 24.04 t64 names)"
# playwright 1.44 'install-deps' targets pre-24.04 package names; install the
# updated equivalents directly instead.
sudo apt-get install -y -q \
    libasound2t64 libicu74 libffi8 libnss3 libnspr4 \
    libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libdbus-1-3 \
    libatspi2.0-0t64 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxrandr2 libgbm1 libxcb1 libxkbcommon0 libpango-1.0-0 libcairo2
./venv/bin/playwright install

echo "==> Seeding config"
[ -f config/probe_config.yaml ] || cp config/probe_config.example.yaml config/probe_config.yaml

echo "==> Verifying offline test suite"
./venv/bin/pytest -m "not requires_srx" -q

cat <<EON

Generator host ready.
Run workloads with the ad-hoc driver (see deploy/srx_workload.py):

    cd $REPO_DIR
    sudo ./venv/bin/python deploy/srx_workload.py --target <TARGET_IP> --src <THIS_IP> --yes all

EON

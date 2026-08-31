#!/usr/bin/env bash
# Install a scoped, passwordless sudoers rule on the SRX client host so the
# dashboard can invoke the probe's root-required workloads over SSH.
#
# This runs *on the client host*, not on the dashboard host. It must be
# invoked interactively (once) as a user with a password-based sudo grant;
# it does NOT accept a password over stdin or store one anywhere.
#
# Usage on the client:
#   sudo ./install-client-sudoers.sh <username> [/path/to/srx]
#
# Example:
#   sudo ./install-client-sudoers.sh alice /home/alice/srx
set -euo pipefail

USER_NAME="${1:-}"
REPO_DIR="${2:-/home/$USER_NAME/srx}"

if [ -z "$USER_NAME" ]; then
    echo "usage: sudo $0 <username> [/path/to/srx]" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (use sudo)" >&2
    exit 2
fi

RULE="$USER_NAME ALL=(root) NOPASSWD: *** /usr/sbin/hping3, /usr/bin/python3, $REPO_DIR/venv/bin/python, $REPO_DIR/venv/bin/python3"

tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile"' EXIT

echo "$RULE" > "$tmpfile"
visudo -c -f "$tmpfile"
install -m 440 -o root -g root "$tmpfile" /etc/sudoers.d/srx-probe

echo "Installed /etc/sudoers.d/srx-probe:"
cat /etc/sudoers.d/srx-probe

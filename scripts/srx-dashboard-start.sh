#!/usr/bin/env bash
# Idempotent launcher for the SRX dashboard. Sources config.env if present.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$HERE/../srx-dashboard"
LOG="$APP_DIR/dashboard.log"
CONFIG="$APP_DIR/config.env"

cd "$APP_DIR" || exit 1

if pgrep -f "[p]ython3 .*srx-dashboard/dashboard\.py" >/dev/null 2>&1 || \
   ss -lnt 2>/dev/null | grep -q ":${SRX_DASH_PORT:-8081} "; then
    echo "$(date -Is) already running" >> "$APP_DIR/start.log"
    exit 0
fi

# shellcheck disable=SC1090
[ -f "$CONFIG" ] && . "$CONFIG"

setsid python3 "$APP_DIR/dashboard.py" >> "$LOG" 2>&1 < /dev/null &
echo "$(date -Is) started pid $!" >> "$APP_DIR/start.log"

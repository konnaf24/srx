#!/usr/bin/env bash
# Idempotent launcher for the ping monitor. Suitable for `@reboot` cron and
# a `*/5 * * * *` watchdog. Sources config.env if present.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$HERE/../pingapp"
LOG="$APP_DIR/server.log"
CONFIG="$APP_DIR/config.env"

cd "$APP_DIR" || exit 1

if pgrep -f "[p]ython3 .*pingapp/server\.py" >/dev/null 2>&1 || \
   ss -lnt 2>/dev/null | grep -q ":${PING_PORT:-8080} "; then
    echo "$(date -Is) already running" >> "$APP_DIR/start.log"
    exit 0
fi

# Wait for networking (WSL boot can be slow).
for _ in $(seq 1 30); do
    ip route get 1.1.1.1 >/dev/null 2>&1 && break
    sleep 2
done

# shellcheck disable=SC1090
[ -f "$CONFIG" ] && . "$CONFIG"

setsid python3 "$APP_DIR/server.py" >> "$LOG" 2>&1 < /dev/null &
echo "$(date -Is) started pid $!" >> "$APP_DIR/start.log"

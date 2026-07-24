#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# NOTE: If Playwright Chromium is needed for live scanning, install it
# separately: `playwright install chromium`. The app automatically falls back
# to demo mode when Chromium is unavailable, so we don't block startup here.

# Workshop devguard — acquires the app port and cleans up stale listeners.
if [ -f /usr/local/lib/workshop-devguard.sh ]; then
    source /usr/local/lib/workshop-devguard.sh
    devguard_acquire "${APP_PORT:-3001}"
fi

exec streamlit run app.py --server.port "${APP_PORT:-3001}" --server.address 0.0.0.0 --server.headless true

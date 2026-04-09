#!/bin/sh
set -e

# Start YouTube WebSocket service in background with auto-restart
(
  set +e
  while true; do
    cd /app/youtube-websocket
    bun run src/index.ts
    echo "YouTube WebSocket service exited, restarting in 2s..."
    sleep 2
  done
) &

# Start Go backend
cd /app
exec ./chat :1535

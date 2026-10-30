#!/usr/bin/env bash
#=============================================================================
# run.sh — Start the AI Guardrails API server in the background
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PORT="${GUARDRAIL_PORT:-8083}"
HOST="${GUARDRAIL_HOST:-0.0.0.0}"
PIDFILE="$DIR/logs/guardrail_server.pid"
LOGFILE="$DIR/logs/guardrail_server.run.log"

mkdir -p logs

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "[ai-guardrails] already running (pid $(cat "$PIDFILE"))"
  echo "  stop: ./scripts/stop.sh"
  exit 0
fi

echo "[ai-guardrails] starting API server on http://$HOST:$PORT/"
nohup python3 guardrail_server.py \
  > "$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"

# Wait for health
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    echo "[ai-guardrails] server started (pid $(cat "$PIDFILE"))"
    echo "  Web UI:    http://$HOST:$PORT/"
    echo "  API:       http://$HOST:$PORT/api/*"
    echo "  Stop:      ./scripts/stop.sh"
    exit 0
  fi
  sleep 0.5
done

echo "[ai-guardrails] WARNING: server did not become healthy. Check $LOGFILE"
exit 1

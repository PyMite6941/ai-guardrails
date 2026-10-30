#!/usr/bin/env bash
#=============================================================================
# stop.sh — Stop the AI Guardrails API server
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PIDFILE="$DIR/logs/guardrail_server.pid"

if [ -f "$PIDFILE" ]; then
  PID=$(cat "$PIDFILE")
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    # Wait up to 5s for exit
    for i in $(seq 1 10); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.5
    done
    if kill -0 "$PID" 2>/dev/null; then
      kill -9 "$PID" 2>/dev/null || true
    fi
    echo "[ai-guardrails] stopped server (pid $PID)"
  else
    echo "[ai-guardrails] server not running (stale pidfile)"
  fi
  rm -f "$PIDFILE"
else
  echo "[ai-guardrails] no pidfile; server not tracked"
fi

# Also stop any tmux-managed guardrail session
if command -v tmux >/dev/null 2>&1; then
  tmux kill-session -t ai-guardrails 2>/dev/null || true
fi

echo "[ai-guardrails] stop complete."

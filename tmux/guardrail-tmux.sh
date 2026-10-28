#!/usr/bin/env bash
#=============================================================================
# AI Guardrails tmux session manager
#=============================================================================
# Manage the guardrail HTTP API server inside a tmux session so it survives
# SSH disconnects and can be attached/detached at will.
#
# Usage:
#   ./tmux/guardrail-tmux.sh start        # start server in tmux (detached)
#   ./tmux/guardrail-tmux.sh stop         # stop the tmux session
#   ./tmux/guardrail-tmux.sh restart      # stop + start
#   ./tmux/guardrail-tmux.sh attach       # attach to the session
#   ./tmux/guardrail-tmux.sh status       # show whether it's running
#   ./tmux/guardrail-tmux.sh logs         # tail the engine log
#
# Environment:
#   GUARDRAIL_SESSION  tmux session name   (default: ai-guardrails)
#   GUARDRAIL_PORT     HTTP port           (default: 8083)
#   GUARDRAIL_HOST     bind host           (default: 0.0.0.0)
#=============================================================================
set -u

SESSION="${GUARDRAIL_SESSION:-ai-guardrails}"
PORT="${GUARDRAIL_PORT:-8083}"
HOST="${GUARDRAIL_HOST:-0.0.0.0}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$DIR/guardrail_server.py"

tmux_running() {
    tmux has-session -t "$SESSION" 2>/dev/null
}

case "${1:-}" in
    start)
        if tmux_running; then
            echo "[ai-guardrails] tmux session '$SESSION' already running."
            echo "  attach: tmux attach -t $SESSION   (or run: $0 attach)"
            exit 0
        fi
        echo "[ai-guardrails] starting guardrail server in tmux session '$SESSION' (port $PORT)..."
        tmux new-session -d -s "$SESSION" -c "$DIR" \
            "GUARDRAIL_PORT=$PORT GUARDRAIL_HOST=$HOST python3 $SERVER"
        # give it a moment to bind
        sleep 1
        if tmux_running; then
            echo "[ai-guardrails] started. Web UI: http://$HOST:$PORT/"
            echo "  attach: $0 attach   |   stop: $0 stop   |   status: $0 status"
        else
            echo "[ai-guardrails] FAILED to start. Check logs: $DIR/logs/ai_guardrails.log"
            exit 1
        fi
        ;;
    stop)
        if ! tmux_running; then
            echo "[ai-guardrails] no tmux session '$SESSION' running."
            exit 0
        fi
        tmux kill-session -t "$SESSION"
        echo "[ai-guardrails] stopped session '$SESSION'."
        ;;
    restart)
        "$0" stop
        sleep 1
        "$0" start
        ;;
    attach)
        if ! tmux_running; then
            echo "[ai-guardrails] no tmux session '$SESSION' running. Start it first: $0 start"
            exit 1
        fi
        tmux attach-session -t "$SESSION"
        ;;
    status)
        if tmux_running; then
            echo "[ai-guardrails] session '$SESSION' is RUNNING."
            echo "  Web UI: http://$HOST:$PORT/"
            echo "  attach: $0 attach"
        else
            echo "[ai-guardrails] session '$SESSION' is NOT running."
            echo "  start:  $0 start"
        fi
        ;;
    logs)
        LOG="$DIR/logs/ai_guardrails.log"
        if [ -f "$LOG" ]; then
            tail -n 50 -f "$LOG"
        else
            echo "[ai-guardrails] no log file yet: $LOG"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|attach|status|logs}"
        exit 1
        ;;
esac

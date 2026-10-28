#!/usr/bin/env bash
#=============================================================================
# session_cleanup.sh — Expired session cleanup (cron job)
#=============================================================================
# Removes expired session tokens from the in-memory session store by
# restarting the guardrail server (which clears the in-memory _SESSIONS
# dict) OR by directly clearing session files if using persistent storage.
#
# Currently, sessions are in-memory only, so this script logs a reminder
# that sessions expire automatically via TTL. In a future version with
# persistent session storage, this would purge expired entries.
#
# Runs hourly by default.
#
# All paths resolved relative to this script — no hardcoded paths.
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

# Load environment
for env_file in /etc/ai-guardrails/env "$HOME/.ai-guardrails.env" ".env"; do
    if [ -f "$env_file" ]; then
        set -a
        . "$env_file"
        set +a
    fi
done

GUARDRAIL_DIR="${GUARDRAIL_DIR:-$DIR}"
GUARDRAIL_LOG_DIR="${GUARDRAIL_LOG_DIR:-$GUARDRAIL_DIR/logs}"

mkdir -p "$GUARDRAIL_LOG_DIR"

LOG_FILE="${GUARDRAIL_LOG_DIR}/session_cleanup_$(date +%Y%m%d).log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "SESSION CLEANUP: Checking for expired sessions..."

# Sessions are in-memory with TTL-based expiration (handled by validate_session).
# This script serves as a checkpoint and log marker.
# If using a persistent session store in the future, purge expired entries here.

SESSION_TTL="${GUARDRAIL_SESSION_TTL:-3600}"
log "SESSION CLEANUP: Session TTL is ${SESSION_TTL} seconds"
log "SESSION CLEANUP: Expired sessions are purged on access (validate_session)"
log "SESSION CLEANUP: No manual cleanup required for in-memory sessions"

exit 0

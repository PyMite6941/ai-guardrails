#!/usr/bin/env bash
#=============================================================================
# log_rotate.sh — Manual log rotation trigger (cron job)
#=============================================================================
# Triggers log rotation on all guardrail log files. Rotation happens
# automatically when a file exceeds LOG_ROTATE_MB, but this cron job ensures
# rotation happens even if no writes occur.
#
# Runs daily at 03:00 by default.
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

LOG_FILE="${GUARDRAIL_LOG_DIR}/log_rotate_$(date +%Y%m%d).log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "LOG ROTATE: Checking log files for rotation..."

cd "$GUARDRAIL_DIR"

OUTPUT=$(python3 guardrail_logging.py rotate 2>&1 || true)
echo "$OUTPUT" | tee -a "$LOG_FILE"

log "LOG ROTATE: Rotation check complete"

exit 0

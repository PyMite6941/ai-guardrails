#!/usr/bin/env bash
#=============================================================================
# update_check.sh — Security update tracker (cron job)
#=============================================================================
# Refreshes component versions and lists any security updates that are due.
# Runs daily at 02:00 by default.
#
# Results are logged to the cron update log. Components past their due date
# are flagged for manual review.
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

LOG_FILE="${GUARDRAIL_LOG_DIR}/update_check_$(date +%Y%m%d).log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "UPDATE CHECK: Refreshing component versions..."

cd "$GUARDRAIL_DIR"

OUTPUT=$(python3 guardrail_updates.py refresh 2>&1 || true)
echo "$OUTPUT" | tee -a "$LOG_FILE"

# Check for due updates
DUE_OUTPUT=$(python3 guardrail_updates.py due 2>&1 || true)

if echo "$DUE_OUTPUT" | grep -q "updates past due"; then
    log "UPDATE ALERT: Security updates are past due:"
    echo "$DUE_OUTPUT" | tee -a "$LOG_FILE"
    exit 1
elif echo "$DUE_OUTPUT" | grep -q "No updates past due"; then
    log "UPDATE CHECK: No updates past due"
    exit 0
else
    log "UPDATE CHECK: Completed (see above for details)"
    exit 0
fi

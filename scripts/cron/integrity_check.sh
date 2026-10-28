#!/usr/bin/env bash
#=============================================================================
# integrity_check.sh — Tamper-evident integrity check (cron job)
#=============================================================================
# Re-hashes all watched guardrail files and compares against the signed
# baseline. Any modification, deletion, or addition is logged as an
# out-of-band alert.
#
# Requires GUARDRAIL_INTEGRITY_KEY to be set for signature verification.
# Runs every 15 minutes by default.
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
GUARDRAIL_INTEGRITY_KEY="${GUARDRAIL_INTEGRITY_KEY:-}"

mkdir -p "$GUARDRAIL_LOG_DIR"

LOG_FILE="${GUARDRAIL_LOG_DIR}/integrity_check_$(date +%Y%m%d).log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

if [ -z "$GUARDRAIL_INTEGRITY_KEY" ]; then
    log "INTEGRITY: GUARDRAIL_INTEGRITY_KEY not set — skipping integrity check"
    log "INTEGRITY: Set GUARDRAIL_INTEGRITY_KEY and run: python3 guardrail_integrity.py init"
    exit 0
fi

cd "$GUARDRAIL_DIR"

RESULT=$(python3 guardrail_integrity.py check 2>&1 || true)

if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('ok') else 1)" 2>/dev/null; then
    log "INTEGRITY: OK — no tampering detected"
    exit 0
else
    log "INTEGRITY ALERT: Tampering detected!"
    echo "$RESULT" | tee -a "$LOG_FILE"
    exit 1
fi

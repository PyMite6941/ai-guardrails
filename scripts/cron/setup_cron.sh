#!/usr/bin/env bash
#=============================================================================
# setup_cron.sh — Install AI Guardrails cron jobs
#=============================================================================
# Installs cron jobs for automated guardrail maintenance:
#   - canary_probe     : Liveness probe every 5 minutes
#   - integrity_check  : Tamper-evident check every 15 minutes
#   - update_check     : Security update check daily at 02:00
#   - session_cleanup  : Expired session cleanup every hour
#   - log_rotate       : Log rotation daily at 03:00
#
# Usage:
#   ./scripts/cron/setup_cron.sh install   # Install all cron jobs
#   ./scripts/cron/setup_cron.sh remove    # Remove all cron jobs
#   ./scripts/cron/setup_cron.sh list      # List current cron jobs
#
# Environment variables (set in /etc/ai-guardrails/env or ~/.ai-guardrails.env):
#   GUARDRAIL_DIR        Installation directory (default: auto-detected)
#   GUARDRAIL_LOG_DIR    Log directory
#   GUARDRAIL_API_KEY    API key for authenticated cron jobs
#   GUARDRAIL_ADMIN_PASSWORD  Password for canary login (if auth enabled)
#
# All paths are resolved relative to this script — nothing is hardcoded to
# a specific user or host.
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

# Load environment from standard locations if they exist
for env_file in /etc/ai-guardrails/env "$HOME/.ai-guardrails.env" ".env"; do
    if [ -f "$env_file" ]; then
        # shellcheck disable=SC1090
        set -a
        . "$env_file"
        set +a
    fi
done

GUARDRAIL_DIR="${GUARDRAIL_DIR:-$DIR}"
GUARDRAIL_LOG_DIR="${GUARDRAIL_LOG_DIR:-$GUARDRAIL_DIR/logs}"
GUARDRAIL_API_KEY="${GUARDRAIL_API_KEY:-}"
GUARDRAIL_ADMIN_PASSWORD="${GUARDRAIL_ADMIN_PASSWORD:-}"

CRON_COMMENT="# AI Guardrails — auto-managed by setup_cron.sh"

CRON_FILES=(
    "canary_probe.sh"
    "integrity_check.sh"
    "update_check.sh"
    "session_cleanup.sh"
    "log_rotate.sh"
)

install_cron() {
    echo "[cron] Installing AI Guardrails cron jobs..."

    # Build the crontab entries
    local crontab_entries=""
    crontab_entries+="${CRON_COMMENT}\n"
    crontab_entries+="*/5 * * * * ${GUARDRAIL_DIR}/scripts/cron/canary_probe.sh >> ${GUARDRAIL_LOG_DIR}/cron_canary.log 2>&1\n"
    crontab_entries+="*/15 * * * * ${GUARDRAIL_DIR}/scripts/cron/integrity_check.sh >> ${GUARDRAIL_LOG_DIR}/cron_integrity.log 2>&1\n"
    crontab_entries+="0 2 * * * ${GUARDRAIL_DIR}/scripts/cron/update_check.sh >> ${GUARDRAIL_LOG_DIR}/cron_update.log 2>&1\n"
    crontab_entries+="0 * * * * ${GUARDRAIL_DIR}/scripts/cron/session_cleanup.sh >> ${GUARDRAIL_LOG_DIR}/cron_session.log 2>&1\n"
    crontab_entries+="0 3 * * * ${GUARDRAIL_DIR}/scripts/cron/log_rotate.sh >> ${GUARDRAIL_LOG_DIR}/cron_rotate.log 2>&1\n"

    # Remove any existing AI Guardrails cron entries first
    remove_cron_silent

    # Append new entries
    {
        crontab -l 2>/dev/null || true
        printf "%b" "$crontab_entries"
    } | crontab -

    echo "[cron] Installed $(echo "$CRON_FILES" | wc -w) cron jobs."
    echo "[cron] Logs: ${GUARDRAIL_LOG_DIR}/cron_*.log"
}

remove_cron() {
    echo "[cron] Removing AI Guardrails cron jobs..."
    remove_cron_silent
    echo "[cron] Removed."
}

remove_cron_silent() {
    crontab -l 2>/dev/null | grep -v "${CRON_COMMENT}" | crontab - 2>/dev/null || true
}

list_cron() {
    echo "[cron] Current AI Guardrails cron jobs:"
    crontab -l 2>/dev/null | grep "${CRON_COMMENT}" -A1 || echo "  (none)"
    echo ""
    crontab -l 2>/dev/null | grep "${CRON_COMMENT}" || true
}

case "${1:-}" in
    install)
        install_cron
        ;;
    remove)
        remove_cron
        ;;
    list)
        list_cron
        ;;
    *)
        echo "Usage: $0 {install|remove|list}"
        exit 1
        ;;
esac

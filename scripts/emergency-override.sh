#!/usr/bin/env bash
#=============================================================================
# emergency-override.sh — AI Guardrails emergency shutdown / re-enable
#=============================================================================
# Staged emergency override for rapid containment of the guardrail system.
#
# Stages (run in order, each can be triggered independently):
#   Stage 1 — CONTAINMENT: Close all ports, block network traffic,
#           stop accepting new connections. The guardrail server is
#           put into "locked down" mode.
#   Stage 2 — CONTAINER: Stop all Docker containers (ai-guardrails,
#           ai-model, outside-model). The AI cannot run.
#   Stage 3 — LOGS: Flush, snapshot, and preserve all guardrail logs
#           to a tamper-evident archive before shutdown.
#   Stage 4 — FULL SHUTDOWN: Stop the guardrail API server entirely.
#
# RE-ENABLING requires safety guards:
#   - Valid admin password (if configured)
#   - Valid 2FA code (if 2FA is enabled)
#   - Emergency lock file removal
#   - Integrity check pass (if key configured)
#
# Usage:
#   ./scripts/emergency-override.sh status
#   ./scripts/emergency-override.sh contain          # Stage 1
#   ./scripts/emergency-override.sh container-stop   # Stage 2
#   ./scripts/emergency-override.sh logs-preserve    # Stage 3
#   ./scripts/emergency-override.sh shutdown         # Stage 4 (full)
#   ./scripts/emergency-override.sh all              # All stages
#   ./scripts/emergency-override.sh reenable --password <pw> --totp <code>
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
GUARDRAIL_PORT="${GUARDRAIL_PORT:-8083}"
GUARDRAIL_HOST="${GUARDRAIL_HOST:-127.0.0.1}"
GUARDRAIL_LOG_DIR="${GUARDRAIL_LOG_DIR:-$GUARDRAIL_DIR/logs}"
GUARDRAIL_ADMIN_PASSWORD="${GUARDRAIL_ADMIN_PASSWORD:-}"
GUARDRAIL_API_KEY="${GUARDRAIL_API_KEY:-}"
GUARDRAIL_2FA_ENABLED="${GUARDRAIL_2FA_ENABLED:-false}"

EMERGENCY_STATE="$GUARDRAIL_LOG_DIR/emergency_state.json"
EMERGENCY_LOCK="$GUARDRAIL_LOG_DIR/emergency.lock"
CONTAINMENT_MARKER="$GUARDRAIL_LOG_DIR/containment.active"

mkdir -p "$GUARDRAIL_LOG_DIR"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$GUARDRAIL_LOG_DIR/emergency-override.log"
}

now_iso() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

write_state() {
    cat > "$EMERGENCY_STATE" <<EOF
{
  "timestamp": "$(now_iso)",
  "containment": $( [ -f "$CONTAINMENT_MARKER" ] && echo "true" || echo "false" ),
  "container_stopped": $( [ -f "$GUARDRAIL_LOG_DIR/container_stopped.active" ] && echo "true" || echo "false" ),
  "logs_preserved": $( [ -f "$GUARDRAIL_LOG_DIR/logs_preserved.active" ] && echo "true" || echo "false" ),
  "shutdown": $( [ -f "$EMERGENCY_LOCK" ] && echo "true" || echo "false" )
}
EOF
}

# ── Stage 1: Containment ──
stage_containment() {
    log "=== STAGE 1: CONTAINMENT ==="
    log "Closing port $GUARDRAIL_PORT and blocking network traffic"

    # Mark containment active
    echo "$(now_iso) - containment triggered" > "$CONTAINMENT_MARKER"

    # If we have iptables/nftables, block the port
    if command -v iptables >/dev/null 2>&1; then
        iptables -A INPUT -p tcp --dport "$GUARDRAIL_PORT" -j DROP 2>/dev/null || true
        iptables -A OUTPUT -p tcp --dport "$GUARDRAIL_PORT" -j DROP 2>/dev/null || true
        log "iptables: blocked port $GUARDRAIL_PORT (in/out)"
    elif command -v nft >/dev/null 2>&1; then
        nft add rule ip filter input tcp dport "$GUARDRAIL_PORT" drop 2>/dev/null || true
        nft add rule ip filter output tcp dport "$GUARDRAIL_PORT" drop 2>/dev/null || true
        log "nftables: blocked port $GUARDRAIL_PORT (in/out)"
    else
        log "WARNING: no iptables/nftables — cannot kernel-block port; relying on server shutdown"
    fi

    # Stop the guardrail server (but keep pidfile for re-enable tracking)
    if [ -f "$GUARDRAIL_DIR/logs/guardrail_server.pid" ]; then
        PID=$(cat "$GUARDRAIL_DIR/logs/guardrail_server.pid" 2>/dev/null || true)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            for i in $(seq 1 10); do
                kill -0 "$PID" 2>/dev/null || break
                sleep 0.5
            done
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null || true
            fi
            log "Guardrail server stopped (pid $PID)"
        fi
    fi

    # Also stop tmux session
    if command -v tmux >/dev/null 2>&1; then
        tmux kill-session -t ai-guardrails 2>/dev/null || true
    fi

    write_state
    log "CONTAINMENT ACTIVE — port $GUARDRAIL_PORT blocked, server stopped"
}

# ── Stage 2: Container stop ──
stage_container_stop() {
    log "=== STAGE 2: CONTAINER STOP ==="

    if ! command -v docker >/dev/null 2>&1; then
        log "WARNING: docker not available — skipping container stop"
        write_state
        return
    fi

    for c in ai-guardrails ai-model outside-model ai-cache; do
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$c"; then
            docker stop "$c" >/dev/null 2>&1 || true
            log "Container stopped: $c"
        fi
    done

    echo "$(now_iso) - containers stopped" > "$GUARDRAIL_LOG_DIR/container_stopped.active"
    write_state
    log "CONTAINER STAGE COMPLETE — all guardrail containers stopped"
}

# ── Stage 3: Logs preserve ──
stage_logs_preserve() {
    log "=== STAGE 3: LOGS PRESERVE ==="

    ARCHIVE_DIR="$GUARDRAIL_LOG_DIR/emergency_archives"
    mkdir -p "$ARCHIVE_DIR"

    ARCHIVE_NAME="guardrail_logs_$(date +%Y%m%d_%H%M%S).tar.gz"
    ARCHIVE_PATH="$ARCHIVE_DIR/$ARCHIVE_NAME"

    # Create a tamper-evident archive with SHA256 manifest
    if [ -d "$GUARDRAIL_LOG_DIR" ]; then
        (cd "$GUARDRAIL_LOG_DIR" && \
         find . -type f \( -name "*.jsonl" -o -name "*.log" \) -print0 2>/dev/null | \
         sort -z | xargs -0 tar czf "$ARCHIVE_PATH" 2>/dev/null || true)

        if [ -f "$ARCHIVE_PATH" ]; then
            sha256sum "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"
            log "Logs archived: $ARCHIVE_PATH"
            log "SHA256: $(cat "$ARCHIVE_PATH.sha256" | awk '{print $1}')"
        fi
    fi

    echo "$(now_iso) - logs preserved to $ARCHIVE_PATH" > "$GUARDRAIL_LOG_DIR/logs_preserved.active"
    write_state
    log "LOGS PRESERVED — archive stored at $ARCHIVE_PATH"
}

# ── Stage 4: Full shutdown ──
stage_shutdown() {
    log "=== STAGE 4: FULL SHUTDOWN ==="

    # Create the emergency lock — this prevents re-enable without safety guards
    echo "$(now_iso) - full shutdown triggered" > "$EMERGENCY_LOCK"

    # Final container cleanup
    if command -v docker >/dev/null 2>&1; then
        docker stop ai-guardrails ai-model outside-model >/dev/null 2>&1 || true
    fi

    # Kill any remaining guardrail processes
    pkill -f "guardrail_server.py" 2>/dev/null || true
    pkill -f "guardrail.py" 2>/dev/null || true

    write_state
    log "FULL SHUTDOWN ACTIVE — system locked. Re-enable requires safety guards."
}

# ── All stages ──
stage_all() {
    stage_containment
    stage_container_stop
    stage_logs_preserve
    stage_shutdown
}

# ── Status ──
cmd_status() {
    echo "=== AI Guardrails Emergency Override Status ==="
    echo ""
    echo "Containment active:   $([ -f "$CONTAINMENT_MARKER" ] && echo "YES" || echo "no")"
    echo "Containers stopped:   $([ -f "$GUARDRAIL_LOG_DIR/container_stopped.active" ] && echo "YES" || echo "no")"
    echo "Logs preserved:       $([ -f "$GUARDRAIL_LOG_DIR/logs_preserved.active" ] && echo "YES" || echo "no")"
    echo "Full shutdown locked: $([ -f "$EMERGENCY_LOCK" ] && echo "YES" || echo "no")"
    echo ""
    echo "2FA enabled:          $GUARDRAIL_2FA_ENABLED"
    echo "Admin password set:   $([ -n "$GUARDRAIL_ADMIN_PASSWORD" ] && echo "yes" || echo "no")"
    echo "API key set:          $([ -n "$GUARDRAIL_API_KEY" ] && echo "yes" || echo "no")"
    echo ""
    if [ -f "$EMERGENCY_STATE" ]; then
        cat "$EMERGENCY_STATE"
    fi
    echo ""
    # Port check
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ":$GUARDRAIL_PORT "; then
            echo "Port $GUARDRAIL_PORT: LISTENING"
        else
            echo "Port $GUARDRAIL_PORT: NOT LISTENING"
        fi
    fi
}

# ── Re-enable with safety guards ──
cmd_reenable() {
    local password=""
    local totp_code=""
    local backup_code=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --password) password="$2"; shift 2 ;;
            --totp)     totp_code="$2"; shift 2 ;;
            --backup)   backup_code="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    log "=== RE-ENABLE ATTEMPT ==="

    # Guard 1: Emergency lock must exist (we only re-enable if locked)
    if [ ! -f "$EMERGENCY_LOCK" ] && [ ! -f "$CONTAINMENT_MARKER" ]; then
        log "No emergency lock found — system already active"
        exit 0
    fi

    # Guard 2: Admin password verification (if configured)
    if [ -n "$GUARDRAIL_ADMIN_PASSWORD" ]; then
        if [ -z "$password" ]; then
            log "RE-ENABLE DENIED: admin password required"
            echo "Usage: $0 reenable --password <pw> [--totp <code>|--backup <code>]"
            exit 1
        fi
        # Verify password via Python
        PW_OK=$(python3 -c "
from guardrail_auth import verify_password
import sys
sys.path.insert(0, '.')
print('YES' if verify_password('$password') else 'NO')
" 2>/dev/null || echo "NO")
        if [ "$PW_OK" != "YES" ]; then
            log "RE-ENABLE DENIED: invalid admin password"
            exit 1
        fi
        log "Password verified"
    fi

    # Guard 3: 2FA verification (if enabled)
    if [ "$GUARDRAIL_2FA_ENABLED" = "true" ]; then
        if [ -z "$totp_code" ] && [ -z "$backup_code" ]; then
            log "RE-ENABLE DENIED: 2FA code required (--totp or --backup)"
            exit 1
        fi
        if [ -n "$totp_code" ]; then
            TOTP_OK=$(python3 -c "
from guardrail_auth import verify_2fa_code
import sys
sys.path.insert(0, '.')
print('YES' if verify_2fa_code('$totp_code') else 'NO')
" 2>/dev/null || echo "NO")
            if [ "$TOTP_OK" != "YES" ]; then
                log "RE-ENABLE DENIED: invalid TOTP code"
                exit 1
            fi
            log "TOTP verified"
        fi
        if [ -n "$backup_code" ]; then
            BACKUP_OK=$(python3 -c "
from guardrail_auth import verify_backup_code
import sys
sys.path.insert(0, '.')
print('YES' if verify_backup_code('$backup_code') else 'NO')
" 2>/dev/null || echo "NO")
            if [ "$BACKUP_OK" != "YES" ]; then
                log "RE-ENABLE DENIED: invalid or used backup code"
                exit 1
            fi
            log "Backup code verified (consumed)"
        fi
    fi

    # Guard 4: Integrity check (if key configured)
    if [ -n "${GUARDRAIL_INTEGRITY_KEY:-}" ]; then
        INTEG_OK=$(python3 guardrail_integrity.py check 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('YES' if d.get('ok') else 'NO')" 2>/dev/null || echo "NO")
        if [ "$INTEG_OK" != "YES" ]; then
            log "RE-ENABLE DENIED: integrity check failed — possible tampering"
            exit 1
        fi
        log "Integrity check passed"
    fi

    # Remove all emergency markers
    rm -f "$EMERGENCY_LOCK" "$CONTAINMENT_MARKER" \
          "$GUARDRAIL_LOG_DIR/container_stopped.active" \
          "$GUARDRAIL_LOG_DIR/logs_preserved.active"

    # Reopen firewall rules if iptables/nftables available
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$GUARDRAIL_PORT" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport "$GUARDRAIL_PORT" -j DROP 2>/dev/null || true
        log "iptables: unblocked port $GUARDRAIL_PORT"
    elif command -v nft >/dev/null 2>&1; then
        log "nftables: manual rule cleanup required for port $GUARDRAIL_PORT"
    fi

    write_state
    log "RE-ENABLE GRANTED — system unlocked. Ready to restart."
    echo ""
    echo "To restart: ./scripts/run.sh"
}

case "${1:-}" in
    status)
        cmd_status
        ;;
    contain|stage1)
        stage_containment
        ;;
    container-stop|stage2)
        stage_container_stop
        ;;
    logs-preserve|stage3)
        stage_logs_preserve
        ;;
    shutdown|stage4)
        stage_shutdown
        ;;
    all)
        stage_all
        ;;
    reenable)
        shift
        cmd_reenable "$@"
        ;;
    *)
        echo "Usage: $0 {status|contain|container-stop|logs-preserve|shutdown|all|reenable}"
        echo ""
        echo "  Stages run in order: contain -> container-stop -> logs-preserve -> shutdown"
        echo "  Re-enable requires: --password (if set) and --totp/--backup (if 2FA enabled)"
        exit 1
        ;;
esac

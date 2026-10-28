#!/usr/bin/env bash
#=============================================================================
# AI Guardrails kill switch (safe, non-destructive)
#=============================================================================
# Called by guardrail.py on critical containment failure (harmful content,
# PII/credential leakage, data exfiltration, system prompt leakage).
# Logs the event and exits 0. In production, extend this to isolate the
# host/container (e.g. stop the gateway, revoke API keys, snapshot logs).
#=============================================================================
set -u

REASON="$(printf '%s' "${1:-no reason provided}" | tr -d '\n\r')"
LOG_DIR="${AI_GUARDRAILS_LOG_DIR:-$(dirname "${BASH_SOURCE[0]}")/../logs}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
HOSTNAME_VAL=$(hostname 2>/dev/null || echo unknown)

mkdir -p "$LOG_DIR"

cat >> "$LOG_DIR/kill-switch.log" <<EOF
[$TIMESTAMP] KILL SWITCH TRIGGERED
  host:     $HOSTNAME_VAL
  reason:   $REASON
  pid:      $$
  cwd:      $(pwd)
EOF

echo "[ai-guardrails] KILL SWITCH triggered: $REASON" >&2
exit 0

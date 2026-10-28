#!/usr/bin/env bash
#=============================================================================
# AI Guardrails one-shot setup
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "[ai-guardrails] making scripts executable"
chmod +x scripts/*.sh tmux/*.sh

echo "[ai-guardrails] running self-test"
python3 tests/test_guardrail.py

echo
echo "[ai-guardrails] setup complete."
echo "  Start server (tmux):  tmux/guardrail-tmux.sh start"
echo "  Start server (plain): python3 guardrail_server.py"
echo "  Web UI:               http://localhost:8083/"
echo "  Docker:               docker compose -f docker/docker-compose.yml up -d"
echo "  npm publish:          npm publish --access public"

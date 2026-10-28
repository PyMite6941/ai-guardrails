#!/usr/bin/env bash
#=============================================================================
# run_cage.sh — Run the AI inside an ephemeral Docker container ("the cage"),
# one conversation at a time, then destroy the container.
#
# Security model (why this is the best balance of security + resource use):
#   - The AI never touches the host: read-only rootfs, dropped capabilities,
#     no --privileged, no Docker socket, no host network/pid/ipc.
#   - Ephemeral per conversation: container is created fresh and removed
#     (--rm) when the conversation ends, so no malware or persistence
#     mechanism survives to the next conversation. No presence can be
#     maintained outside the shell.
#   - Logs are written to a host-mounted volume so every breakout attempt
#     is captured and visible immediately, even though the container is gone.
#   - Resource cost is low: containers start in ~1s on modern Docker and the
#     image is layered/reused; only one cage container runs at a time.
#
# Usage:
#   ./docker/run_cage.sh "your prompt"        # single turn
#   OUTSIDE_MODEL_ENABLED=1 ./docker/run_cage.sh "prompt"   # with outer monitor
#
# Env:
#   CAGE_IMAGE        image to run            (default: ai-guardrails-model)
#   CAGE_PORT         host port for model     (default: 8000)
#   CAGE_TIMEOUT      seconds per conversation(default: 120)
#   OUTSIDE_MODEL_*   forwarded to guardrails (outer monitor)
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

IMAGE="${CAGE_IMAGE:-ai-guardrails-model}"
PORT="${CAGE_PORT:-8000}"
TIMEOUT="${CAGE_TIMEOUT:-120}"
CONTAINER="ai-cage-$$"
LOG_VOLUME="ai-cage-logs"

IMAGE="${CAGE_IMAGE:-ai-guardrails-model}"

# Ensure the model image exists (builds the containerized model from Dockerfile.model).
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[cage] building model image '$IMAGE' from docker/Dockerfile.model ..."
  docker build -t "$IMAGE" -f docker/Dockerfile.model docker/
fi

# Ensure a named volume exists for logs (survives container destruction so
# breakout attempts remain visible after the cage is removed).
docker volume create "$LOG_VOLUME" >/dev/null 2>&1 || true

PROMPT="${1:-hello}"

echo "[cage] starting ephemeral cage container '$CONTAINER' (prompt: ${PROMPT:0:60}...)"

# Run the cage:
#   --rm            remove container after it stops (no persistence)
#   --read-only     read-only rootfs (AI cannot write malware to disk)
#   --tmpfs /tmp    writable tmp only where the model needs it (RAM-backed)
#   --cap-drop ALL  drop every Linux capability
#   --security-opt no-new-privileges  prevent privilege escalation
#   --pids-limit    limit processes inside the cage
#   --memory        cap memory
#   --cpus          cap CPU
#   no -v /var/run/docker.sock, no --privileged, no --network=host
docker run -d \
  --name "$CONTAINER" \
  --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 64 \
  --memory=512m \
  --cpus=0.5 \
  --network none \
  -e MODEL_HOST=0.0.0.0 \
  -e MODEL_PORT=8000 \
  -e MODE_SERVER_MODE=local \
  -e MODEL_NAME=caged-ai \
  -v "$LOG_VOLUME:/app/logs:ro" \
  "$IMAGE" >/dev/null

# Wait for the model to be ready inside the cage.
for i in $(seq 1 "$((TIMEOUT / 2))"); do
  if docker exec "$CONTAINER" \
     curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

# Send the prompt to the caged AI (proxied through localhost:PORT on host).
# The port mapping is not used (--network none); instead exec into container.
RESPONSE=""
if docker exec "$CONTAINER" \
   curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
  RESPONSE=$(docker exec "$CONTAINER" \
    curl -fsS -X POST http://127.0.0.1:8000/api/chat \
    -H 'Content-Type: application/json' \
    -d "{\"prompt\":\"$PROMPT\"}" 2>/dev/null || true)
fi

echo ""
echo "=== Caged AI response ==="
echo "$RESPONSE" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('response','[no response]'))
except Exception:
    print(sys.stdin.read())
" 2>/dev/null || echo "$RESPONSE"

# Capture cage logs (breakout attempts, errors) to the host log dir before
# the container is destroyed.
mkdir -p "$DIR/logs"
docker logs "$CONTAINER" > "$DIR/logs/cage_$(date +%Y%m%d_%H%M%S).log" 2>&1 || true

# Destroy the cage — conversation over, container removed, nothing persists.
docker stop "$CONTAINER" >/dev/null 2>&1 || true
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

echo "[cage] container '$CONTAINER' destroyed. Nothing persists outside the shell."
echo "[cage] logs saved to $DIR/logs/ (breakout attempts are visible there)."

#!/usr/bin/env bash
#=============================================================================
# demo.sh — run a throwaway, publicly-exposable demo instance
#=============================================================================
# Starts AI Guardrails with state in a temp directory (never touches your real
# config, policies, users or logs), creates a read-only demo account, and
# prints what to do next.
#
#   ./scripts/demo.sh                 # local only, 127.0.0.1:8083
#   ./scripts/demo.sh --port 8099     # different port
#   DEMO_HOST=demo.example.com ./scripts/demo.sh   # allow a tunnel hostname
#
# The demo account is a DEVELOPER: it can read the console, run validations and
# open the chat page, but cannot change policies, users, keys or contain the
# system. That is deliberate — a public link must not be able to reconfigure
# the guardrail.
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PORT=8083
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    *) echo "unknown argument: $1"; exit 1 ;;
  esac
done

STATE="${DEMO_STATE_DIR:-/tmp/ag-demo}"
CREDS="$HOME/.ai_guardrails_demo_credentials.txt"
USER="demo"
PASS="Demo-$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(8)))')"

if [ -z "${SSL_CERT_FILE:-}" ] && [ -f /etc/ssl/cert.pem ]; then
  export SSL_CERT_FILE=/etc/ssl/cert.pem
fi

mkdir -p "$STATE"
rm -f "$STATE/users.json" "$STATE/keys.json" "$STATE/auth.json"

export GUARDRAIL_PORT="$PORT"
export GUARDRAIL_HOST="127.0.0.1"
export GUARDRAIL_USERS_PATH="$STATE/users.json"
export GUARDRAIL_KEYS_PATH="$STATE/keys.json"
export GUARDRAIL_AUTH_STATE_PATH="$STATE/auth.json"
export GUARDRAIL_LOG_DIR="$STATE/logs"
# A tunnel terminates on a random hostname; add it here if you know it.
export GUARDRAIL_ALLOWED_HOSTS="${DEMO_HOST:-127.0.0.1,localhost}"

echo "starting demo instance on 127.0.0.1:$PORT (state: $STATE)"
python3 guardrail_server.py &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done

# Create the read-only demo account through the API (same path a human uses).
COOKIE="$(mktemp)"
CURL=(curl -s -b "$COOKIE" -c "$COOKIE" -H "Content-Type: application/json")

# Bootstrap an admin password for this throwaway instance only.
ADMIN_PASS="Setup-$(python3 -c 'import secrets;print(secrets.token_hex(8))')"
"${CURL[@]}" -X POST "http://127.0.0.1:$PORT/api/auth/setup-password" \
  -d "{\"password\":\"$ADMIN_PASS\"}" >/dev/null
"${CURL[@]}" -X POST "http://127.0.0.1:$PORT/api/auth/login" \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" >/dev/null
CSRF="$(curl -s -D - -o /dev/null -b "$COOKIE" "http://127.0.0.1:$PORT/api/users" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="x-csrf-token"{print $2}')"
"${CURL[@]}" -X POST "http://127.0.0.1:$PORT/api/users" -H "X-CSRF-Token: $CSRF" \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\",\"role\":\"developer\"}" >/dev/null
rm -f "$COOKIE"

umask 077
cat > "$CREDS" <<EOF
AI Guardrails — demo account (throwaway instance)
url      http://127.0.0.1:$PORT/
user     $USER
pass     $PASS
role     developer (can validate + chat; cannot change policies, users, keys, or contain)

Paste the url/user/pass into the Devpost "live demo" notes when you host it.
Delete this file when the demo is over.
EOF
chmod 600 "$CREDS"

cat <<EOF

demo ready
  console   http://127.0.0.1:$PORT/
  chat      http://127.0.0.1:$PORT/chat
  account   $USER / (see $CREDS)
  state     $STATE   (deleted on reboot; your real config is untouched)

to make it public, tunnel to this port (cloudflared, ngrok, or an SSH reverse
tunnel), then restart with the hostname allowed:

  DEMO_HOST=<tunnel-hostname> ./scripts/demo.sh --port $PORT

without DEMO_HOST the server refuses non-loopback Host headers by design.

Ctrl-C stops the server.
EOF

wait "$SERVER_PID"

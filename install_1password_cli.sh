#!/usr/bin/env bash
#=============================================================================
# install_1password_cli.sh — Install 1Password CLI on Linux
#
# Downloads the official 1Password CLI binary, installs it to /usr/local/bin,
# and walks through initial sign-in.
#
# Usage: ./install_1password_cli.sh
#=============================================================================
set -euo pipefail

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
  echo "Unsupported architecture: $ARCH" >&2
  exit 1
fi

URL="https://downloads.1password.com/linux/op/1password-cli-latest.${ARCH}.tar.gz"

echo "==> Downloading 1Password CLI from $URL"
curl -fsSL "$URL" | sudo tar xzv -C /usr/local/bin

echo "==> Installed:"
op --version

echo ""
echo "==> Next steps:"
echo "  1. Sign in:   op signin my.1password.com <your_email>"
echo "  2. Export:    export OP_SESSION_my=<session_key_from_output>"
echo "  3. Store key: op item create --vault Private --title \"Nebius API Key\" --category password --username=nebius --password=\"<your_api_key>\""
echo ""
echo "WARNING: Never paste API keys into chat. Use 1Password sharing to share secrets."

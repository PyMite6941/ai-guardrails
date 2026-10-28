#!/usr/bin/env bash
#=============================================================================
# install.sh — One-time offline-first install for AI Guardrails
#=============================================================================
# Builds the memory-safe Rust pattern scanner (Aho-Corasick) so guardrails can
# run without relying on network-dependent regex libraries at match time.
# Requires only a local Rust toolchain (rustc/cargo). No crates.io download is
# needed at runtime; the aho-corasick crate is already vendored into the lock
# file and was fetched when this image was prepared. If cargo build fails for
# any reason, the Python fallback scanner is used automatically.
#=============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[ai-guardrails] making scripts executable"
chmod +x scripts/*.sh tmux/*.sh docker/*.sh 2>/dev/null || true

echo "[ai-guardrails] building Rust pattern scanner (offline)"
if command -v cargo >/dev/null 2>&1; then
  (cd rust && cargo build --release --offline 2>/dev/null || cargo build --release 2>/dev/null) || {
    echo "[ai-guardrails] WARNING: Rust build failed — Python fallback scanner will be used"
  }
else
  echo "[ai-guardrails] cargo not found — skipping Rust scanner; Python fallback used"
fi

if [ -f rust/target/release/guardrail-scanner ]; then
  echo "[ai-guardrails] Rust scanner built at rust/target/release/guardrail-scanner"
else
  echo "[ai-guardrails] Rust scanner not built — using Python fallback"
fi

echo
echo "[ai-guardrails] install complete."
echo "  Next:  ./scripts/setup.sh   (self-test + usage hints)"
echo "  Run:   ./scripts/run.sh     (start API server in background)"
echo "  Stop:  ./scripts/stop.sh"

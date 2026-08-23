#!/bin/zsh
# Launcher for a VoiceOS local-mcp integration.
#
# LAW: stdout is the MCP wire. Nothing in this script may ever print to stdout —
# every diagnostic goes to stderr (>&2). One stray `echo` and the client sees a
# malformed JSON-RPC frame.
#
# Runtime ladder. The integration is zero-runtime-dependency,
# node-native TypeScript, so the fast paths need no `npm install` inside their 30s
# connect gate:
#   1. bun            — executes TS natively, if the machine happens to have it
#   2. node >= 22.18  — type stripping on by default (stable since v24.12.0)
#   3. local tsx      — only if a node_modules/ was pre-warmed here
#   4. npx --yes tsx  — last resort; downloads, slow, measured in the cold-start budget
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.bun/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

BUN=""
for candidate in "$HOME/.bun/bin/bun" /opt/homebrew/bin/bun "$(command -v bun 2>/dev/null || true)"; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then BUN="$candidate"; break; fi
done
if [[ -n "$BUN" ]]; then
  exec "$BUN" "$SCRIPT_DIR/server.ts" "$@"
fi

NODE="$(command -v node 2>/dev/null || true)"
if [[ -n "$NODE" ]]; then
  # Type stripping is on by default from v22.18.0 / v23.6.0 (https://nodejs.org/api/typescript.html)
  if "$NODE" -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit((a>=24||(a===23&&b>=6)||(a===22&&b>=18))?0:1)'; then
    exec "$NODE" "$SCRIPT_DIR/server.ts" "$@"
  fi
  echo "[run.sh] node $("$NODE" -v) is too old for native TypeScript; falling back to tsx." >&2
fi

if [[ -x "$SCRIPT_DIR/node_modules/.bin/tsx" ]]; then
  exec "$SCRIPT_DIR/node_modules/.bin/tsx" "$SCRIPT_DIR/server.ts" "$@"
fi

echo "[run.sh] No bun, no modern node, no local tsx — using npx (slow first launch)." >&2
exec npx --yes tsx "$SCRIPT_DIR/server.ts" "$@"

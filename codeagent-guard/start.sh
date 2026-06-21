#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi
if [[ -f .env.permissions ]]; then
  set -a
  source .env.permissions
  set +a
fi
exec python3 server.py --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"

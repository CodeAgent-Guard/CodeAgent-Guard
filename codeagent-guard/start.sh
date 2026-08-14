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

log_dir="${GUARD_DATA_DIR:-$PWD/data}"
log_file="$log_dir/server.log"

if [[ "${1:-}" == "--logs" ]]; then
  mkdir -p "$log_dir"
  touch "$log_file"
  exec tail -n 40 -F "$log_file"
fi

if (( $# > 0 )); then
  echo "Usage: ./start.sh [--logs]" >&2
  exit 2
fi

mkdir -p "$log_dir"
exec python3 -u server.py --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"

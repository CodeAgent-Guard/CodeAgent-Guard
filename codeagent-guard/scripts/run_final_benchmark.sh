#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
repo_root="$(cd "$project_dir/.." && pwd)"

python_bin="${CODEAGENT_BENCHMARK_PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    python_bin="python"
  else
    echo "python3 was not found. Install python3 or set CODEAGENT_BENCHMARK_PYTHON." >&2
    exit 127
  fi
fi

cd "$repo_root"

exec "$python_bin" agent-attack-benchmark/run_benchmark.py \
  --guard codeagent_guard \
  --dataset agent-attack-benchmark/benchmark.jsonl \
  --out benchmark_results/final_run.json \
  --trace-dir runs/final_trace \
  --audit-db runs/final_audit.sqlite \
  "$@"

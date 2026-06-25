from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guard.policy import PolicyEngine
from guard.taint import SourceType


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(
        len(ordered) * ratio
    ) - 1))
    return round(ordered[index], 4)


def run(iterations: int = 1000) -> dict:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        policy = PolicyEngine(workspace)

        large_readme = "\n".join(
            f"BENCHMARK_MARKER document line {index} path "
            f"{workspace}/docs/file-{index}.md"
            for index in range(500)
        )
        started = time.perf_counter()
        _, readme_entities = policy.register_context(
            large_readme,
            SourceType.WORKSPACE_FILE,
            "workspace/LARGE_README.md",
            trace_id="stress-large-readme",
        )
        large_readme_ms = (time.perf_counter() - started) * 1000

        long_log = "\n".join(
            f"pytest case {index}: BENCHMARK_MARKER "
            f"grep TODO {workspace}/README.md"
            for index in range(1000)
        )
        started = time.perf_counter()
        _, log_entities = policy.register_context(
            long_log,
            SourceType.LOG_OUTPUT,
            "pytest-long.log",
            trace_id="stress-long-log",
        )
        long_log_ms = (time.perf_counter() - started) * 1000

        taint_trace = "stress-taint-match"
        for index in range(1000):
            policy.register_context(
                f"read {workspace}/generated/file-{index}.txt",
                SourceType.WORKSPACE_FILE,
                f"workspace/docs/source-{index}.md",
                trace_id=taint_trace,
            )
        started = time.perf_counter()
        matches = policy.taint_tracker.match_taint(
            "read_file",
            {"path": str(workspace / "generated" / "file-999.txt")},
            trace_id=taint_trace,
        )
        taint_match_ms = (time.perf_counter() - started) * 1000

        calls = [
            (
                "read_file",
                {"path": str(workspace / "README.md")},
                "Summarize README",
            ),
            (
                "run_command",
                {"cmd": "pytest -q"},
                "Run pytest -q",
            ),
            (
                "send_email",
                {
                    "to": "external@example.test",
                    "body": "BENCHMARK_MARKER",
                },
                "Send a benchmark report to external@example.test",
            ),
            (
                "http_request",
                {"url": "http://127.0.0.1/admin", "method": "GET"},
                "Inspect a benchmark endpoint",
            ),
        ]
        latencies = []
        actions = {"allow": 0, "ask": 0, "deny": 0}
        for index in range(iterations):
            tool, args, task = calls[index % len(calls)]
            started = time.perf_counter()
            decision = policy.evaluate(
                tool,
                args,
                source="agent",
                trace_id=f"stress-policy-{index}",
                task=task,
                task_allowed_tools={tool},
            )
            latencies.append((time.perf_counter() - started) * 1000)
            actions[decision.action] += 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "iterations": iterations,
            "actions": actions,
            "avg_ms": round(statistics.mean(latencies), 4),
            "p50_ms": percentile(latencies, 0.50),
            "p95_ms": percentile(latencies, 0.95),
            "p99_ms": percentile(latencies, 0.99),
            "max_ms": round(max(latencies), 4),
            "large_readme": {
                "chars": len(large_readme),
                "entities": len(readme_entities),
                "elapsed_ms": round(large_readme_ms, 4),
            },
            "long_pytest_log": {
                "chars": len(long_log),
                "entities": len(log_entities),
                "elapsed_ms": round(long_log_ms, 4),
            },
            "taint_entity_match": {
                "registered_sources": 1000,
                "matches": len(matches),
                "elapsed_ms": round(taint_match_ms, 4),
            },
            "scope_statement": (
                "This local stress result describes the current machine and "
                "deterministic workload only."
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/stability/stress_ct_trm_policy.json"),
    )
    args = parser.parse_args()
    report = run(args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

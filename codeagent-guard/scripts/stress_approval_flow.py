from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guard.audit import AuditStore
from guard.contracts import ToolCall
from guard.policy import PolicyEngine
from guard.state import RuntimeStateStore
from guard.tools import ToolProxy
from guard.transparency import TransparencyService


class NoExecutionExpected:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, tool: str, args: dict) -> dict:
        self.calls += 1
        return {"mocked": True}


def run(count: int = 100, workers: int = 10) -> dict:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        state = RuntimeStateStore(root / "state.db")
        executor = NoExecutionExpected()
        proxy = ToolProxy(
            workspace,
            AuditStore(root / "audit.db"),
            PolicyEngine(workspace, state_store=state),
            root / "outbox",
            executor=executor,
            transparency=TransparencyService(),
            state_store=state,
            approval_ttl_seconds=120,
        )

        def create(index: int) -> tuple[dict, float]:
            started = time.perf_counter()
            outcome = proxy.authorize(ToolCall(
                tool="send_email",
                args={
                    "to": f"review-{index}@example.test",
                    "subject": f"Benchmark {index}",
                    "body": "BENCHMARK_MARKER",
                },
                trace_id=f"stress-approval-{index}",
                task="Send an external benchmark review",
                agent_id="opencode",
                allowed_tools=("send_email",),
            ))
            return outcome, (time.perf_counter() - started) * 1000

        with ThreadPoolExecutor(max_workers=workers) as pool:
            created = list(pool.map(create, range(count)))
        outcomes = [item[0] for item in created]
        create_latencies = [item[1] for item in created]
        approval_ids = [item["approval_id"] for item in outcomes]

        query_started = time.perf_counter()
        queried = [
            proxy.get_approval_status(approval_id)
            for approval_id in approval_ids
        ]
        query_ms = (time.perf_counter() - query_started) * 1000

        resolve_latencies = []
        for index, approval_id in enumerate(approval_ids):
            started = time.perf_counter()
            proxy.resolve_approval(
                approval_id,
                approve=index % 2 == 0,
            )
            resolve_latencies.append((time.perf_counter() - started) * 1000)

        statuses = [
            proxy.get_approval_status(approval_id)["status"]
            for approval_id in approval_ids
        ]
        audit = AuditStore(root / "audit.db").verify()
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "approval_count": count,
            "concurrency": workers,
            "unique_approval_ids": len(set(approval_ids)),
            "pending_query_count": sum(
                item and item["status"] == "pending" for item in queried
            ),
            "approved_count": statuses.count("approved"),
            "rejected_count": statuses.count("rejected"),
            "guard_executor_calls": executor.calls,
            "create_avg_ms": round(statistics.mean(create_latencies), 4),
            "create_p95_ms": sorted(create_latencies)[
                max(0, int(len(create_latencies) * 0.95) - 1)
            ],
            "query_total_ms": round(query_ms, 4),
            "resolve_avg_ms": round(statistics.mean(resolve_latencies), 4),
            "audit_chain_valid": audit["valid"],
            "audit_event_count": audit["events"],
            "scope_statement": (
                "This stress run uses delegated external calls and a local "
                "temporary SQLite database; no email is sent."
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/stability/stress_approval_flow.json"),
    )
    args = parser.parse_args()
    report = run(args.count, args.workers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

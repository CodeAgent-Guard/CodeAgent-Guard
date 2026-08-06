"""Run the Agent attack benchmark against CodeAgent Guard.

The default terminal output is intentionally clean so it can be used directly
in report screenshots. The runner evaluates policy decisions only; it does not
execute shell commands, send email, access real networks, or read real secrets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = Path(__file__).resolve().parent
GUARD_ROOT = REPO_ROOT / "codeagent-guard"
DEFAULT_DATASET = BENCH_DIR / "benchmark.jsonl"
DEFAULT_OUT = REPO_ROOT / "benchmark_results" / "final_run.json"
DEFAULT_TRACE_DIR = REPO_ROOT / "runs" / "final_trace"
DEFAULT_AUDIT_DB = REPO_ROOT / "runs" / "final_audit.sqlite"

sys.path.insert(0, str(GUARD_ROOT))

from guard.catalog import TOOL_NAMES  # noqa: E402
from guard.policy import PolicyEngine  # noqa: E402


def display_path(path: Path) -> str:
    """Return a stable, screenshot-friendly path."""
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def percent(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return round(float(numerator) / float(denominator) * 100, 2)


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * ratio) - 1))
    return round(ordered[index], 4)


def load_cases(dataset: Path) -> list[dict[str, Any]]:
    with dataset.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def make_policy(workspace: Path) -> PolicyEngine:
    return PolicyEngine(workspace=workspace, allowed_tools=set(TOOL_NAMES))


def expected_action(case: dict[str, Any]) -> str:
    return str(
        case.get("expected_action")
        or case.get("expected_guard_decision")
        or case.get("expected")
        or "allow"
    ).lower()


def is_malicious(case: dict[str, Any], expected: str) -> bool:
    if "malicious" in case:
        return bool(case["malicious"])
    return expected == "deny"


def run_benchmark(
    cases: list[dict[str, Any]],
    *,
    workspace: Path,
    approved: bool = False,
    detail: bool = False,
) -> dict[str, Any]:
    policy = make_policy(workspace)
    all_tools = set(TOOL_NAMES)
    results: list[dict[str, Any]] = []
    latencies: list[float] = []

    for index, case in enumerate(cases, start=1):
        expected = expected_action(case)
        malicious = is_malicious(case, expected)
        allowed_tools = set(case.get("task_allowed_tools", [])) or all_tools

        started = time.perf_counter()
        policy_error = ""
        try:
            decision = policy.evaluate(
                case["tool"],
                case.get("args", {}),
                source=case.get("source", "user"),
                tainted=bool(case.get("tainted", False)),
                approved=approved,
                task_allowed_tools=allowed_tools,
            )
            actual = decision.action
            risk_level = decision.risk_level
            reasons = list(decision.reasons)
        except Exception as exc:  # Keep benchmark side-effect free and auditable.
            policy_error = f"{type(exc).__name__}: {exc}"
            actual = "deny"
            risk_level = "critical"
            reasons = ["policy_exception_conservative_deny", type(exc).__name__]
        elapsed_ms = (time.perf_counter() - started) * 1000
        latencies.append(elapsed_ms)

        if expected == "ask" and approved:
            passed = actual in {"ask", "allow"}
        else:
            passed = actual == expected

        row = {
            "index": index,
            "id": case.get("id", f"CASE-{index:04d}"),
            "category": case.get("category", ""),
            "subcategory": case.get("subcategory", ""),
            "description": case.get("description", ""),
            "tool": case["tool"],
            "args": case.get("args", {}),
            "source": case.get("source", "user"),
            "tainted": bool(case.get("tainted", False)),
            "malicious": malicious,
            "expected_action": expected,
            "actual_action": actual,
            "risk_level": risk_level,
            "reasons": reasons,
            "policy_error": policy_error,
            "latency_ms": round(elapsed_ms, 4),
            "passed": passed,
            "attack_intervened": malicious and actual in {"ask", "deny"},
            "strong_denied": malicious and actual == "deny",
            "false_negative": malicious and actual == "allow",
            "false_positive": (not malicious) and actual == "deny",
            "normal_disruption": (not malicious) and actual in {"ask", "deny"},
        }
        results.append(row)

        if detail:
            status = "PASS" if passed else "FAIL"
            print(
                f"[{status}] {row['id']} tool={row['tool']} "
                f"expected={expected} actual={actual} risk={row['risk_level']}"
            )

    return {"results": results, "latencies": latencies}


def compute_report(
    benchmark: dict[str, Any],
    *,
    guard: str,
    dataset: Path,
    out: Path,
    trace_dir: Path,
    audit_db: Path,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = benchmark["results"]
    latencies: list[float] = benchmark["latencies"]

    total = len(results)
    malicious = [item for item in results if item["malicious"]]
    normal = [item for item in results if not item["malicious"]]
    correct = sum(1 for item in results if item["passed"])
    failed = total - correct
    false_negatives = [item for item in malicious if item["false_negative"]]
    false_positives = [item for item in normal if item["false_positive"]]
    normal_disruptions = [item for item in normal if item["normal_disruption"]]
    attack_interventions = [item for item in malicious if item["attack_intervened"]]
    strong_denies = [item for item in malicious if item["strong_denied"]]

    by_action = Counter(item["actual_action"] for item in results)
    by_tool: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "correct": 0, "deny": 0})
    by_category: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "correct": 0, "malicious": 0, "intervened": 0, "fn": 0}
    )

    for item in results:
        tool_group = by_tool[item["tool"]]
        tool_group["total"] += 1
        tool_group["correct"] += int(item["passed"])
        tool_group["deny"] += int(item["actual_action"] == "deny")

        category_group = by_category[item["category"] or "uncategorized"]
        category_group["total"] += 1
        category_group["correct"] += int(item["passed"])
        category_group["malicious"] += int(item["malicious"])
        category_group["intervened"] += int(item["attack_intervened"])
        category_group["fn"] += int(item["false_negative"])

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "guard": guard,
        "dataset": display_path(dataset),
        "total_samples": total,
        "malicious_samples": len(malicious),
        "normal_confirm_samples": len(normal),
        "correct": correct,
        "failed": failed,
        "accuracy": percent(correct, total),
        "attack_block_rate": percent(len(attack_interventions), len(malicious)),
        "strong_deny_rate": percent(len(strong_denies), len(malicious)),
        "fn_rate": percent(len(false_negatives), len(malicious)),
        "fp_rate": percent(len(false_positives), len(normal)),
        "normal_disruption_rate": percent(len(normal_disruptions), len(normal)),
        "false_negative_count": len(false_negatives),
        "false_positive_count": len(false_positives),
        "normal_disruption_count": len(normal_disruptions),
        "actual_actions": dict(by_action),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
        "p50_latency_ms": percentile(latencies, 0.50),
        "p95_latency_ms": percentile(latencies, 0.95),
        "p99_latency_ms": percentile(latencies, 0.99),
        "trace_dir": display_path(trace_dir),
        "audit_db": display_path(audit_db),
        "result_saved": display_path(out),
    }

    return {
        "summary": summary,
        "by_tool": dict(by_tool),
        "by_category": dict(by_category),
        "failures": [item for item in results if not item["passed"]],
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "results": results,
    }


def write_json_report(report: dict[str, Any], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)


def write_trace_files(report: dict[str, Any], trace_dir: Path) -> None:
    trace_dir.mkdir(parents=True, exist_ok=True)
    events_path = trace_dir / "trace_events.jsonl"
    failures_path = trace_dir / "failures.jsonl"

    with events_path.open("w", encoding="utf-8") as handle:
        for item in report["results"]:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    with failures_path.open("w", encoding="utf-8") as handle:
        for item in report["failures"]:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def audit_hash(prev_hash: str, event: dict[str, Any]) -> str:
    payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def write_audit_db(report: dict[str, Any], audit_db: Path) -> None:
    audit_db.parent.mkdir(parents=True, exist_ok=True)
    if audit_db.exists():
        audit_db.unlink()

    conn = sqlite3.connect(audit_db)
    try:
        conn.execute(
            """
            CREATE TABLE run_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE decisions (
                seq INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                expected_action TEXT NOT NULL,
                actual_action TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                passed INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                reasons_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """
        )
        for key, value in report["summary"].items():
            conn.execute(
                "INSERT INTO run_metadata(key, value) VALUES (?, ?)",
                (key, json.dumps(value, ensure_ascii=False)),
            )

        prev = "0" * 64
        for item in report["results"]:
            event = {
                "seq": item["index"],
                "case_id": item["id"],
                "tool": item["tool"],
                "expected_action": item["expected_action"],
                "actual_action": item["actual_action"],
                "risk_level": item["risk_level"],
                "passed": item["passed"],
                "latency_ms": item["latency_ms"],
                "reasons": item["reasons"],
            }
            current = audit_hash(prev, event)
            conn.execute(
                """
                INSERT INTO decisions(
                    seq, case_id, tool, expected_action, actual_action,
                    risk_level, passed, latency_ms, reasons_json,
                    prev_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["index"],
                    item["id"],
                    item["tool"],
                    item["expected_action"],
                    item["actual_action"],
                    item["risk_level"],
                    int(item["passed"]),
                    item["latency_ms"],
                    json.dumps(item["reasons"], ensure_ascii=False),
                    prev,
                    current,
                ),
            )
            prev = current
        conn.commit()
    finally:
        conn.close()


def write_markdown_report(report: dict[str, Any], path: Path) -> None:
    summary = report["summary"]
    lines = [
        "# CodeAgent Guard Benchmark",
        "",
        f"- Dataset: `{summary['dataset']}`",
        f"- Total samples: {summary['total_samples']}",
        f"- Malicious samples: {summary['malicious_samples']}",
        f"- Normal/confirm samples: {summary['normal_confirm_samples']}",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Correct | {summary['correct']} |",
        f"| Failed | {summary['failed']} |",
        f"| Accuracy | {summary['accuracy']}% |",
        f"| Attack block rate | {summary['attack_block_rate']}% |",
        f"| Strong deny rate | {summary['strong_deny_rate']}% |",
        f"| FN rate | {summary['fn_rate']}% |",
        f"| FP rate | {summary['fp_rate']}% |",
        f"| Normal disruption rate | {summary['normal_disruption_rate']}% |",
        f"| P95 latency | {summary['p95_latency_ms']} ms |",
        "",
        f"- Trace dir: `{summary['trace_dir']}`",
        f"- Audit db: `{summary['audit_db']}`",
        f"- Result saved: `{summary['result_saved']}`",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_clean_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print()
    print("CodeAgent Guard Benchmark")
    print(f"Guard: {summary['guard']}")
    print(f"Dataset: {summary['dataset']}")
    print(f"Total samples: {summary['total_samples']}")
    print(f"Malicious samples: {summary['malicious_samples']}")
    print(f"Normal/confirm samples: {summary['normal_confirm_samples']}")
    print()
    print(f"Correct: {summary['correct']}")
    print(f"Failed: {summary['failed']}")
    print(f"Accuracy: {summary['accuracy']:.2f}%")
    print(f"Attack block rate: {summary['attack_block_rate']:.2f}%")
    print(f"FN rate: {summary['fn_rate']:.2f}%")
    print(f"FP rate: {summary['fp_rate']:.2f}%")
    print(f"P95 latency: {summary['p95_latency_ms']:.4f} ms")
    print()
    print(f"Trace dir: {summary['trace_dir']}/")
    print(f"Audit db: {summary['audit_db']}")
    print(f"Result saved: {summary['result_saved']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CodeAgent Guard benchmark")
    parser.add_argument("--guard", default="codeagent_guard", help="Guard implementation name for the report")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="Benchmark JSONL dataset")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output JSON report path")
    parser.add_argument("--trace-dir", type=Path, default=DEFAULT_TRACE_DIR, help="Trace output directory")
    parser.add_argument("--audit-db", type=Path, default=DEFAULT_AUDIT_DB, help="SQLite audit output path")
    parser.add_argument("--approved", action="store_true", help="Treat ASK cases as pre-approved")
    parser.add_argument("--detail", action="store_true", help="Print each case decision before the summary")
    parser.add_argument("--summary", action="store_true", help="Print the clean screenshot summary")
    parser.add_argument("--report", action="store_true", help="Also write a Markdown report next to --out")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Backward-compatible output directory; ignored when --out is provided",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.guard != "codeagent_guard":
        raise SystemExit("Only --guard codeagent_guard is supported by this runner.")

    out = args.out
    if args.output_dir is not None and out == DEFAULT_OUT:
        out = args.output_dir / "benchmark_run_report.json"

    dataset = args.dataset
    if not dataset.exists():
        raise SystemExit(f"Dataset not found: {dataset}")

    cases = load_cases(dataset)
    benchmark = run_benchmark(
        cases,
        workspace=dataset.parent,
        approved=args.approved,
        detail=args.detail,
    )
    report = compute_report(
        benchmark,
        guard=args.guard,
        dataset=dataset,
        out=out,
        trace_dir=args.trace_dir,
        audit_db=args.audit_db,
    )

    write_json_report(report, out)
    write_trace_files(report, args.trace_dir)
    write_audit_db(report, args.audit_db)
    if args.report:
        write_markdown_report(report, out.with_suffix(".md"))

    # Keep default output screenshot-friendly. --summary is accepted for the
    # report command line, but the clean summary is also the default output.
    print_clean_summary(report)


if __name__ == "__main__":
    main()

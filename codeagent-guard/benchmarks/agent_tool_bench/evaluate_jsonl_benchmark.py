from __future__ import annotations

import argparse
import csv
import json
import socket
import statistics
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from guard.policy import PolicyEngine


DEFAULT_MODES = ("baseline_rules", "full_ct_trm")
ACTIONS = ("allow", "ask", "deny")


def load_jsonl(path: Path) -> list[dict]:
    cases = []
    seen_ids: set[str] = set()
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw.strip():
            continue
        try:
            case = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"line {line_number} is not valid JSON: {exc}"
            ) from exc
        for field in (
            "id",
            "category",
            "description",
            "tool",
            "args",
            "expected_action",
            "malicious",
        ):
            if field not in case:
                raise ValueError(
                    f"line {line_number} is missing required field {field}"
                )
        case_id = str(case["id"])
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        if case["expected_action"] not in ACTIONS:
            raise ValueError(
                f"{case_id} has invalid expected_action "
                f"{case['expected_action']!r}"
            )
        if not isinstance(case["args"], dict):
            raise ValueError(f"{case_id} args must be an object")
        cases.append(case)
    if not cases:
        raise ValueError("benchmark is empty")
    return cases


def _mock_getaddrinfo(host, port, *args, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", int(port or 443)),
        )
    ]


def _percent(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator * 100, 2) if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(
        len(ordered) - 1,
        int((len(ordered) - 1) * percentile),
    ))
    return round(ordered[index], 4)


def _prepare_workspace(workspace: Path) -> None:
    for relative in (
        "src",
        "tests",
        "config",
        "docs",
        "reports",
        "data",
    ):
        (workspace / relative).mkdir(parents=True, exist_ok=True)
    fixtures = {
        "README.md": "# Benchmark workspace\n",
        "src/main.py": "def main():\n    return 0\n",
        "tests/test_main.py": "def test_main():\n    assert True\n",
        "config/app.json": "{}\n",
        "docs/guide.md": "# Guide\n",
    }
    for relative, content in fixtures.items():
        (workspace / relative).write_text(content, encoding="utf-8")


def _classification_metrics(results: list[dict]) -> dict:
    malicious = [item for item in results if item["malicious"]]
    benign = [item for item in results if not item["malicious"]]
    true_positive = sum(
        item["malicious"] and item["actual_action"] == "deny"
        for item in results
    )
    false_negative = sum(
        item["malicious"] and item["actual_action"] != "deny"
        for item in results
    )
    false_positive = sum(
        not item["malicious"] and item["actual_action"] == "deny"
        for item in results
    )
    true_negative = sum(
        not item["malicious"] and item["actual_action"] != "deny"
        for item in results
    )
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive else 0.0
    )
    recall = true_positive / len(malicious) if malicious else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    intervention = sum(
        item["malicious"] and item["actual_action"] in {"ask", "deny"}
        for item in results
    )
    return {
        "malicious_cases": len(malicious),
        "benign_cases": len(benign),
        "true_positive": true_positive,
        "false_negative": false_negative,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "malicious_block_rate": _percent(true_positive, len(malicious)),
        "attack_intervention_rate": _percent(intervention, len(malicious)),
        "false_positive_rate": _percent(false_positive, len(benign)),
        "false_negative_rate": _percent(false_negative, len(malicious)),
        "deny_precision": round(precision * 100, 2),
        "deny_recall": round(recall * 100, 2),
        "deny_f1": round(f1 * 100, 2),
    }


def _action_metrics(results: list[dict]) -> dict:
    confusion = {
        expected: {actual: 0 for actual in ACTIONS}
        for expected in ACTIONS
    }
    per_action = {}
    for item in results:
        confusion[item["expected_action"]][item["actual_action"]] += 1
    for action in ACTIONS:
        true_positive = confusion[action][action]
        predicted = sum(confusion[expected][action] for expected in ACTIONS)
        expected = sum(confusion[action].values())
        precision = true_positive / predicted if predicted else 0.0
        recall = true_positive / expected if expected else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )
        per_action[action] = {
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1": round(f1 * 100, 2),
            "support": expected,
        }
    return {
        "confusion_matrix": confusion,
        "per_action": per_action,
        "macro_f1": round(
            statistics.mean(item["f1"] for item in per_action.values()),
            2,
        ),
    }


def run_mode(cases: list[dict], mode: str) -> dict:
    results = []
    latencies = []
    category_buckets: dict[str, Counter] = defaultdict(Counter)
    tool_buckets: dict[str, Counter] = defaultdict(Counter)
    reasons: Counter[str] = Counter()
    patterns: Counter[str] = Counter()

    for case in cases:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir()
            _prepare_workspace(workspace)
            policy = PolicyEngine(workspace)
            trace_id = f"jsonl-{mode}-{case['id']}"
            if case.get("tainted"):
                policy.register_context(
                    json.dumps(case["args"], ensure_ascii=False),
                    str(case.get("source", "unknown")),
                    str(
                        case.get("carrier")
                        or case.get("scenario")
                        or case["id"]
                    ),
                    trace_id=trace_id,
                )
            started = time.perf_counter()
            with patch(
                "guard.network_safety.socket.getaddrinfo",
                side_effect=_mock_getaddrinfo,
            ):
                decision = policy.evaluate(
                    str(case["tool"]),
                    case["args"],
                    source=str(case.get("source", "user")),
                    tainted=bool(case.get("tainted", False)),
                    task_allowed_tools=set(
                        case.get("task_allowed_tools") or [case["tool"]]
                    ),
                    trace_id=trace_id,
                    task=str(case.get("description") or case["scenario"]),
                    ct_trm_mode=mode,
                )
            latency = (time.perf_counter() - started) * 1000
            assessment = decision.assessment or {}
            risk_patterns = sorted({
                item.get("pattern_id")
                for item in assessment.get("risk_patterns", [])
                if item.get("pattern_id")
            })
            passed = decision.action == case["expected_action"]
            item = {
                "id": case["id"],
                "category": case["category"],
                "subcategory": case.get("subcategory", ""),
                "description": case["description"],
                "tool": case["tool"],
                "source": case.get("source", "user"),
                "tainted": bool(case.get("tainted", False)),
                "malicious": bool(case["malicious"]),
                "expected_action": case["expected_action"],
                "actual_action": decision.action,
                "risk_level": decision.risk_level,
                "passed": passed,
                "reasons": decision.reasons,
                "patterns": risk_patterns,
                "taint_flow": bool(assessment.get("taint_matches")),
                "chain_risk": bool(assessment.get("chain_findings")),
                "latency_ms": round(latency, 4),
                "args": case["args"],
            }
            results.append(item)
            latencies.append(latency)
            for reason in decision.reasons:
                reasons[reason] += 1
            for pattern_id in risk_patterns:
                patterns[pattern_id] += 1
            for bucket in (
                category_buckets[case["category"]],
                tool_buckets[case["tool"]],
            ):
                bucket["total"] += 1
                bucket["passed"] += int(passed)
                bucket[f"expected_{case['expected_action']}"] += 1
                bucket[f"actual_{decision.action}"] += 1
                bucket["false_positive"] += int(
                    not case["malicious"] and decision.action == "deny"
                )
                bucket["false_negative"] += int(
                    case["malicious"] and decision.action != "deny"
                )

    passed_count = sum(item["passed"] for item in results)
    binary = _classification_metrics(results)
    action = _action_metrics(results)
    return {
        "mode": mode,
        "total_cases": len(results),
        "passed": passed_count,
        "failed": len(results) - passed_count,
        "accuracy": _percent(passed_count, len(results)),
        "expected_actions": dict(Counter(
            item["expected_action"] for item in results
        )),
        "actual_actions": dict(Counter(
            item["actual_action"] for item in results
        )),
        **binary,
        **action,
        "average_latency_ms": round(statistics.mean(latencies), 4),
        "p50_latency_ms": _percentile(latencies, 0.50),
        "p95_latency_ms": _percentile(latencies, 0.95),
        "p99_latency_ms": _percentile(latencies, 0.99),
        "taint_flow_detected_count": sum(
            item["taint_flow"] for item in results
        ),
        "chain_risk_detected_count": sum(
            item["chain_risk"] for item in results
        ),
        "reason_coverage": dict(reasons.most_common()),
        "pattern_coverage": dict(sorted(patterns.items())),
        "by_category": {
            key: dict(value)
            for key, value in category_buckets.items()
        },
        "by_tool": {
            key: dict(value)
            for key, value in tool_buckets.items()
        },
        "failures": [item for item in results if not item["passed"]],
        "results": results,
    }


def _summary(result: dict) -> dict:
    fields = (
        "mode",
        "total_cases",
        "passed",
        "failed",
        "accuracy",
        "malicious_cases",
        "benign_cases",
        "malicious_block_rate",
        "attack_intervention_rate",
        "false_positive_rate",
        "false_negative_rate",
        "deny_precision",
        "deny_recall",
        "deny_f1",
        "macro_f1",
        "average_latency_ms",
        "p95_latency_ms",
        "taint_flow_detected_count",
        "chain_risk_detected_count",
    )
    return {field: result[field] for field in fields}


def write_reports(
    input_path: Path,
    output_dir: Path,
    mode_results: dict[str, dict],
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark": str(input_path.resolve()),
        "scope": (
            "Policy-only deterministic replay. Tool side effects are never "
            "executed. Tainted samples register their argument payload as "
            "source context; missing multi-step or filesystem setup is not "
            "reconstructed from expected labels."
        ),
        "modes": {
            mode: _summary(result)
            for mode, result in mode_results.items()
        },
    }
    (output_dir / "benchmark_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    for mode, result in mode_results.items():
        (output_dir / f"{mode}_results.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        with (output_dir / f"{mode}_failures.jsonl").open(
            "w",
            encoding="utf-8",
        ) as handle:
            for failure in result["failures"]:
                handle.write(json.dumps(
                    failure,
                    ensure_ascii=False,
                ) + "\n")

    full = mode_results.get("full_ct_trm") or next(iter(mode_results.values()))
    category_fields = (
        "category",
        "total",
        "passed",
        "expected_allow",
        "expected_ask",
        "expected_deny",
        "actual_allow",
        "actual_ask",
        "actual_deny",
        "false_positive",
        "false_negative",
    )
    with (output_dir / "category_breakdown.csv").open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=category_fields)
        writer.writeheader()
        for category, values in full["by_category"].items():
            writer.writerow({
                field: category if field == "category" else values.get(field, 0)
                for field in category_fields
            })

    mode_rows = "\n".join(
        f"| {mode} | {result['passed']}/{result['total_cases']} | "
        f"{result['accuracy']}% | {result['malicious_block_rate']}% | "
        f"{result['attack_intervention_rate']}% | "
        f"{result['false_positive_rate']}% | "
        f"{result['false_negative_rate']}% | {result['deny_f1']}% | "
        f"{result['p95_latency_ms']} |"
        for mode, result in mode_results.items()
    )
    confusion = full["confusion_matrix"]
    confusion_rows = "\n".join(
        f"| {expected} | {confusion[expected]['allow']} | "
        f"{confusion[expected]['ask']} | {confusion[expected]['deny']} |"
        for expected in ACTIONS
    )
    category_rows = "\n".join(
        f"| {category} | {values.get('passed', 0)}/"
        f"{values.get('total', 0)} | {values.get('actual_deny', 0)} | "
        f"{values.get('false_positive', 0)} | "
        f"{values.get('false_negative', 0)} |"
        for category, values in full["by_category"].items()
    )
    markdown = f"""# benchmark.jsonl Evaluation

## Scope

- Input cases: {full['total_cases']}
- Malicious: {full['malicious_cases']}
- Benign/confirmation: {full['benign_cases']}
- Policy decisions only; no tool is executed.
- Tainted samples register their argument payload as untrusted source context.
- Missing filesystem and prior-turn setup is not inferred from expected labels.

## Core Metrics

| Mode | Exact | Accuracy | Malicious block | Intervention | FPR | FNR | Deny F1 | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{mode_rows}

## Full CT-TRM Confusion Matrix

| Expected / Actual | Allow | Ask | Deny |
|---|---:|---:|---:|
{confusion_rows}

## Full CT-TRM Category Breakdown

| Category | Exact | Denied | FP | FN |
|---|---:|---:|---:|---:|
{category_rows}

## Metric Definitions

- Accuracy: exact `allow/ask/deny` agreement.
- Malicious block rate: malicious samples classified `deny`.
- Intervention rate: malicious samples classified `ask` or `deny`.
- FPR: benign/confirmation samples incorrectly classified `deny`.
- FNR: malicious samples not classified `deny`.
- Deny precision/recall/F1: binary metrics with `deny` as the positive class.

The detailed failures are in `full_ct_trm_failures.jsonl`. These results apply
only to the supplied dataset and current deterministic policy implementation.
"""
    (output_dir / "benchmark_report.md").write_text(
        markdown,
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark", type=Path)
    parser.add_argument(
        "--modes",
        nargs="+",
        default=list(DEFAULT_MODES),
        choices=(
            "baseline_rules",
            "rules_plus_source",
            "rules_plus_taint",
            "ct_trm_without_chain",
            "full_ct_trm",
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/benchmark_jsonl"),
    )
    args = parser.parse_args()
    cases = load_jsonl(args.benchmark)
    results = {
        mode: run_mode(cases, mode)
        for mode in args.modes
    }
    summary = write_reports(args.benchmark, args.output_dir, results)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

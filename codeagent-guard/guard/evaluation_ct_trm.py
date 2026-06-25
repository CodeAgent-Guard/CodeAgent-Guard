from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import statistics
import socket
import tempfile
import time
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

from .network_safety import NetworkTargetError, validate_public_http_target
from .policy import PolicyEngine
from .taint import SourceType


MODES = (
    "no_guard_mock",
    "baseline_rules",
    "rules_plus_source",
    "rules_plus_taint",
    "ct_trm_without_chain",
    "full_ct_trm",
)


def load_cases(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [
            json.loads(raw)
            for raw in text.splitlines()
            if raw.strip()
        ]
    if not isinstance(data, list):
        raise ValueError("benchmark root must be a list or JSONL records")
    return [_normalize_case(case) for case in data]


def _normalize_case(case: dict) -> dict:
    if "expected_guard_decision" in case:
        return case
    required = {
        "id",
        "category",
        "tool",
        "args",
        "expected_action",
    }
    missing = sorted(required.difference(case))
    if missing:
        raise ValueError(
            f"benchmark case is missing required fields: {missing}"
        )
    return {
        **case,
        "split": str(case.get("split", "external_jsonl")),
        "subcategory": str(case.get("subcategory", "")),
        "user_task": str(
            case.get("description")
            or case.get("scenario")
            or case["id"]
        ),
        "expected_guard_decision": str(case["expected_action"]),
        "workspace_setup": (
            case.get("workspace_setup")
            or case.get("setup")
            or []
        ),
        "expected_tool_call": {
            "tool": str(case["tool"]),
            "args": case.get("args") or {},
            "source": str(case.get("source", "user")),
            "tainted": bool(case.get("tainted", False)),
        },
    }


def _percent(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator * 100, 2) if denominator else 0.0


def _private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, math.ceil(
        percentile * len(ordered)
    ) - 1))
    return round(ordered[rank], 4)


def _expand(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {
            key: _expand(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_expand(item, replacements) for item in value]
    if isinstance(value, str):
        for marker, replacement in replacements.items():
            value = value.replace(marker, replacement)
        return value
    return value


def _final_call(case: dict) -> dict:
    call = case.get("expected_tool_call")
    if isinstance(call, dict):
        return call
    sequence = case.get("expected_sequence") or []
    return sequence[-1] if sequence else {}


def _prepare_workspace(workspace: Path) -> None:
    (workspace / "docs").mkdir(parents=True, exist_ok=True)
    (workspace / "src").mkdir(parents=True, exist_ok=True)
    (workspace / "tmp").mkdir(parents=True, exist_ok=True)
    (workspace / "README.md").write_text(
        "# BENCHMARK_MARKER\nSafe local benchmark workspace.\n",
        encoding="utf-8",
    )
    (workspace / "src" / "app.py").write_text(
        "def hello():\n    return 'BENCHMARK_MARKER'\n",
        encoding="utf-8",
    )


def _apply_setup(
    policy: PolicyEngine,
    setup: list[dict],
    trace_id: str,
) -> list[str]:
    notes = []
    for item in setup:
        kind = item.get("kind", "context")
        if kind == "context":
            policy.register_context(
                str(item.get("content", "")),
                SourceType(item.get("source_type", "workspace_file")),
                str(item.get("origin", "benchmark")),
                trace_id=trace_id,
            )
        elif kind == "result":
            policy.observe_tool_result(
                str(item["tool"]),
                item.get("args", {}),
                item.get("result", {}),
                str(item.get("decision", "allow")),
                trace_id=trace_id,
            )
        elif kind == "file":
            path = Path(str(item["path"]))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(item.get("content", "")), encoding="utf-8")
        elif kind == "symlink":
            path = Path(str(item["path"]))
            target = Path(str(item["target"]))
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.symlink_to(target)
            except OSError:
                path.write_text("BENCHMARK_MARKER simulated symlink", encoding="utf-8")
                notes.append("symlink_creation_unavailable")
        elif kind == "mock_redirect":
            notes.append("redirect_is_policy_input_only")
    return notes


def _runtime_patches(stack: ExitStack, setup: list[dict]) -> None:
    stack.enter_context(patch(
        "guard.network_safety.socket.getaddrinfo",
        side_effect=lambda host, port, *args, **kwargs: [(
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", int(port or 443)),
        )],
    ))
    realpaths = {
        os.path.normcase(os.path.abspath(str(item["path"]))): str(
            item["target"]
        )
        for item in setup
        if item.get("kind") == "symlink"
    }
    if not realpaths:
        return
    original = os.path.realpath

    def simulated_realpath(value, *args, **kwargs):
        key = os.path.normcase(os.path.abspath(str(value)))
        seen = set()
        while key in realpaths and key not in seen:
            seen.add(key)
            next_value = realpaths[key]
            key = os.path.normcase(os.path.abspath(str(next_value)))
        if seen:
            return str(Path(key))
        return original(value, *args, **kwargs)

    stack.enter_context(patch(
        "guard.taint.os.path.realpath",
        side_effect=simulated_realpath,
    ))


def _benchmark_source_type(value: str) -> SourceType:
    aliases = {
        "agent": SourceType.LLM_PLAN,
        "user": SourceType.USER_TASK,
        "runtime_log": SourceType.LOG_OUTPUT,
        "repository_content": SourceType.WORKSPACE_FILE,
    }
    if value in aliases:
        return aliases[value]
    try:
        return SourceType(value)
    except ValueError:
        return SourceType.UNKNOWN


def _suggested_fix(result: dict) -> str:
    category = result["category"]
    suggestions = {
        "path_traversal_and_symlink": (
            "Normalize repeated and encoded separators, then verify realpath "
            "against the authorized root immediately before execution."
        ),
        "ssrf_and_metadata": (
            "Resolve hostnames through a controlled resolver and re-check every "
            "redirect target and resolved IP against private/metadata ranges."
        ),
        "secret_exfiltration": (
            "Inspect all sink fields and encoded/chunked payload representations "
            "using hashed secret provenance."
        ),
        "dangerous_shell_and_encoded_payload": (
            "Tokenize shell syntax and model substitutions, decoders, pipelines, "
            "and generated-script execution."
        ),
        "package_script_poisoning": (
            "Parse package lifecycle configuration and connect discovered hooks "
            "to the command that triggers them."
        ),
    }
    return suggestions.get(
        category,
        "Add a deterministic feature or provenance rule for this missed case.",
    )


def run_mode(mode: str, cases: list[dict]) -> dict:
    if mode not in MODES:
        raise ValueError(f"unsupported mode: {mode}")
    results = []
    latencies: list[float] = []
    action_counts: Counter[str] = Counter()
    expected_counts: Counter[str] = Counter()
    category_counts: dict[str, Counter] = defaultdict(Counter)
    split_counts: dict[str, Counter] = defaultdict(Counter)
    pattern_coverage: Counter[str] = Counter()
    reason_coverage: Counter[str] = Counter()
    tool_coverage: Counter[str] = Counter()
    source_coverage: Counter[str] = Counter()

    for case in cases:
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            workspace = root / "workspace"
            fake_home = root / "fake_home"
            fake_root = root / "fake_root"
            fake_shared = fake_root / "shared"
            mock_server = root / "mock_server"
            for path in (workspace, fake_home, fake_root, fake_shared, mock_server):
                path.mkdir(parents=True, exist_ok=True)
            _prepare_workspace(workspace)
            replacements = {
                "${WORKSPACE}": str(workspace),
                "${FAKE_HOME}": str(fake_home),
                "${FAKE_ROOT}": str(fake_root),
                "${MOCK_SERVER}": str(mock_server),
            }
            expanded = _expand(case, replacements)
            call = _final_call(expanded)
            tool = str(call.get("tool", ""))
            args = call.get("args") or {}
            expected = expanded["expected_guard_decision"]
            trace_id = f"atb-{case['id']}-{mode}"
            setup_notes: list[str] = []

            if mode == "no_guard_mock":
                started = time.perf_counter()
                action = "allow"
                risk_level = "low"
                reasons: list[str] = []
                assessment: dict = {}
                latency = (time.perf_counter() - started) * 1000
            else:
                policy = PolicyEngine(
                    workspace,
                    internal_domains={
                        "codeguard.local",
                        "company.local",
                        "localhost",
                    },
                    open_directory_roots=[fake_shared],
                    external_write_roots=[fake_shared],
                )
                setup_notes = _apply_setup(
                    policy,
                    expanded.get("workspace_setup") or [],
                    trace_id,
                )
                if call.get("tainted"):
                    policy.register_context(
                        json.dumps(args, ensure_ascii=False, default=str),
                        _benchmark_source_type(
                            str(call.get("source", "unknown"))
                        ),
                        str(
                            expanded.get("carrier")
                            or expanded.get("scenario")
                            or expanded["id"]
                        ),
                        trace_id=trace_id,
                    )
                _runtime_patches(
                    stack,
                    expanded.get("workspace_setup") or [],
                )
                started = time.perf_counter()
                decision = policy.evaluate(
                    tool,
                    args,
                    source=str(call.get("source", "agent")),
                    tainted=bool(call.get("tainted", False)),
                    task_allowed_tools={tool},
                    trace_id=trace_id,
                    task=str(expanded["user_task"]),
                    ct_trm_mode=mode,
                )
                for setup_item in expanded.get("workspace_setup") or []:
                    if setup_item.get("kind") != "mock_redirect":
                        continue
                    try:
                        validate_public_http_target(
                            str(setup_item.get("location", ""))
                        )
                    except NetworkTargetError as exc:
                        decision.add(
                            "deny",
                            (
                                "critical"
                                if exc.reason == "ssrf_private_network"
                                else "medium"
                            ),
                            f"redirect_{exc.reason}",
                        )
                for setup_item in expanded.get("workspace_setup") or []:
                    if setup_item.get("kind") != "mock_dns":
                        continue
                    private_dns = any(
                        _private_address(address)
                        for address in setup_item.get("addresses", [])
                    )
                    if private_dns:
                        decision.add(
                            "deny",
                            "critical",
                            "dns_rebinding_private_address",
                        )
                latency = (time.perf_counter() - started) * 1000
                action = decision.action
                risk_level = decision.risk_level
                reasons = decision.reasons
                assessment = decision.assessment or {}

            latencies.append(latency)
            expected_counts[expected] += 1
            action_counts[action] += 1
            passed = action == expected
            false_positive = expected == "allow" and action != "allow"
            false_negative = expected == "deny" and action != "deny"
            category_bucket = category_counts[expanded["category"]]
            split_bucket = split_counts[expanded["split"]]
            for bucket in (category_bucket, split_bucket):
                bucket["total"] += 1
                bucket["passed"] += int(passed)
                bucket[action] += 1
                bucket["false_positive"] += int(false_positive)
                bucket["false_negative"] += int(false_negative)

            patterns = sorted({
                item.get("pattern_id")
                for item in assessment.get("risk_patterns", [])
                if item.get("pattern_id")
            })
            chain_patterns = sorted({
                item.get("pattern_id")
                for item in assessment.get("chain_findings", [])
                if item.get("pattern_id")
            })
            for pattern in patterns:
                pattern_coverage[pattern] += 1
            for reason in reasons:
                reason_coverage[reason] += 1
            tool_coverage[tool] += 1
            for setup in expanded.get("workspace_setup") or []:
                if setup.get("kind") == "context":
                    source_coverage[str(setup.get("source_type"))] += 1

            result = {
                "id": expanded["id"],
                "split": expanded["split"],
                "category": expanded["category"],
                "subcategory": expanded["subcategory"],
                "description": str(
                    expanded.get("description")
                    or expanded.get("user_task")
                    or ""
                ),
                "tool": tool,
                "args": args,
                "source": str(call.get("source", "agent")),
                "tainted": bool(call.get("tainted", False)),
                "malicious": bool(
                    expanded.get(
                        "malicious",
                        expected == "deny",
                    )
                ),
                "expected_action": expected,
                "actual_action": action,
                "risk_level": risk_level,
                "passed": passed,
                "false_positive": false_positive,
                "false_negative": false_negative,
                "reasons": reasons,
                "patterns": patterns,
                "chain_patterns": chain_patterns,
                "taint_flow": bool(assessment.get("taint_matches")),
                "chain_risk": bool(assessment.get("chain_findings")),
                "latency_ms": round(latency, 4),
                "setup_notes": setup_notes,
            }
            if not passed:
                result["suggested_fix"] = _suggested_fix(result)
            results.append(result)

    total = len(results)
    passed_count = sum(item["passed"] for item in results)
    false_positives = [item for item in results if item["false_positive"]]
    false_negatives = [item for item in results if item["false_negative"]]
    attacks = [item for item in results if item["malicious"]]
    benign = [item for item in results if not item["malicious"]]
    normal = [
        item for item in results if item["expected_action"] == "allow"
    ]
    confirmation = [
        item for item in results if item["expected_action"] == "ask"
    ]
    expected_deny = [
        item for item in results if item["expected_action"] == "deny"
    ]
    strong_blocks = sum(
        item["actual_action"] == "deny" for item in attacks
    )
    interventions = sum(
        item["actual_action"] in {"ask", "deny"} for item in attacks
    )
    complete_misses = sum(
        item["actual_action"] == "allow" for item in attacks
    )
    deny_misses = sum(
        item["actual_action"] != "deny" for item in expected_deny
    )
    normal_disruptions = sum(
        item["actual_action"] != "allow" for item in normal
    )
    overblocks = sum(
        item["actual_action"] == "deny" for item in confirmation
    )
    false_deny = sum(
        item["actual_action"] == "deny" for item in benign
    )
    deny_precision = (
        strong_blocks / (strong_blocks + false_deny)
        if strong_blocks + false_deny else 0.0
    )
    deny_recall = strong_blocks / len(attacks) if attacks else 0.0
    deny_f1 = (
        2 * deny_precision * deny_recall / (deny_precision + deny_recall)
        if deny_precision + deny_recall else 0.0
    )
    confusion = {
        expected: {actual: 0 for actual in ("allow", "ask", "deny")}
        for expected in ("allow", "ask", "deny")
    }
    for item in results:
        confusion[item["expected_action"]][item["actual_action"]] += 1
    per_action: dict[str, dict[str, float | int]] = {}
    for action in ("allow", "ask", "deny"):
        true_positive = confusion[action][action]
        predicted = sum(
            confusion[expected][action]
            for expected in ("allow", "ask", "deny")
        )
        support = sum(confusion[action].values())
        precision = true_positive / predicted if predicted else 0.0
        recall = true_positive / support if support else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )
        per_action[action] = {
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1": round(f1 * 100, 2),
            "support": support,
        }
    holdout = [item for item in results if item["split"] == "holdout"]
    return {
        "mode": mode,
        "total_cases": total,
        "cases_by_split": {
            key: dict(value) for key, value in sorted(split_counts.items())
        },
        "cases_by_category": {
            key: dict(value) for key, value in sorted(category_counts.items())
        },
        "expected_allow": expected_counts["allow"],
        "expected_ask": expected_counts["ask"],
        "expected_deny": expected_counts["deny"],
        "actual_allow": action_counts["allow"],
        "actual_ask": action_counts["ask"],
        "actual_deny": action_counts["deny"],
        "passed": passed_count,
        "accuracy": _percent(passed_count, total),
        "holdout_accuracy": _percent(
            sum(item["passed"] for item in holdout),
            len(holdout),
        ),
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "false_positive_rate": _percent(
            len(false_positives),
            expected_counts["allow"],
        ),
        "false_negative_rate": _percent(
            len(false_negatives),
            expected_counts["deny"],
        ),
        "malicious_cases": len(attacks),
        "benign_cases": len(benign),
        "malicious_block_count": strong_blocks,
        "malicious_block_rate": _percent(strong_blocks, len(attacks)),
        "strong_block_count": strong_blocks,
        "strong_block_rate": _percent(strong_blocks, len(attacks)),
        "attack_intervention_count": interventions,
        "attack_intervention_rate": _percent(
            interventions,
            len(attacks),
        ),
        "complete_miss_count": complete_misses,
        "complete_miss_rate": _percent(complete_misses, len(attacks)),
        "complete_false_negative_count": complete_misses,
        "complete_false_negative_rate": _percent(
            complete_misses,
            len(attacks),
        ),
        "deny_miss_count": deny_misses,
        "deny_miss_rate": _percent(deny_misses, len(expected_deny)),
        "normal_task_interference_count": normal_disruptions,
        "normal_task_interference_rate": _percent(
            normal_disruptions,
            len(normal),
        ),
        "normal_task_disruption_count": normal_disruptions,
        "normal_task_disruption_rate": _percent(
            normal_disruptions,
            len(normal),
        ),
        "overblocking_count": overblocks,
        "overblocking_rate": _percent(
            overblocks,
            len(confirmation),
        ),
        "deny_precision": round(deny_precision * 100, 2),
        "deny_recall": round(deny_recall * 100, 2),
        "deny_f1": round(deny_f1 * 100, 2),
        "confusion_matrix": confusion,
        "per_action": per_action,
        "macro_f1": round(
            statistics.mean(
                float(value["f1"]) for value in per_action.values()
            ),
            2,
        ),
        "guard_block_rate": _percent(action_counts["deny"], total),
        "ask_rate": _percent(action_counts["ask"], total),
        "attack_trigger_rate": _percent(len(attacks), total),
        "attack_success_rate_mock": _percent(
            sum(item["actual_action"] == "allow" for item in attacks),
            len(attacks),
        ),
        "taint_flow_detected_count": sum(
            item["taint_flow"] for item in results
        ),
        "chain_risk_detected_count": sum(
            item["chain_risk"] for item in results
        ),
        "risk_pattern_coverage": dict(sorted(pattern_coverage.items())),
        "reason_coverage": dict(sorted(reason_coverage.items())),
        "tool_coverage": dict(sorted(tool_coverage.items())),
        "source_coverage": dict(sorted(source_coverage.items())),
        "policy_latency_avg_ms": round(statistics.mean(latencies), 4),
        "policy_latency_p50_ms": _percentile(latencies, 0.50),
        "policy_latency_p95_ms": _percentile(latencies, 0.95),
        "p95_latency_ms": _percentile(latencies, 0.95),
        "policy_latency_p99_ms": _percentile(latencies, 0.99),
        "failure_cases": [item for item in results if not item["passed"]],
        "false_positive_cases": false_positives,
        "false_negative_cases": false_negatives,
        "results": results,
    }


def _summary_row(result: dict) -> dict:
    fields = (
        "mode", "total_cases", "passed", "accuracy", "holdout_accuracy",
        "actual_allow", "actual_ask", "actual_deny",
        "false_positive_count", "false_negative_count",
        "false_positive_rate", "false_negative_rate",
        "malicious_block_rate", "strong_block_rate",
        "attack_intervention_rate", "complete_miss_rate",
        "complete_false_negative_rate", "deny_miss_rate",
        "normal_task_interference_rate", "normal_task_disruption_rate",
        "overblocking_rate", "deny_precision", "deny_recall",
        "deny_f1", "macro_f1",
        "guard_block_rate", "ask_rate", "attack_success_rate_mock",
        "taint_flow_detected_count", "chain_risk_detected_count",
        "policy_latency_avg_ms", "policy_latency_p50_ms",
        "policy_latency_p95_ms", "policy_latency_p99_ms",
    )
    return {field: result[field] for field in fields}


def write_reports(
    cases_path: Path,
    output_dir: Path,
    mode_results: dict[str, dict],
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    for mode, result in mode_results.items():
        (output_dir / f"{mode}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark": str(cases_path),
        "total_cases": next(iter(mode_results.values()))["total_cases"],
        "modes": {
            mode: _summary_row(result)
            for mode, result in mode_results.items()
        },
        "scope_statement": (
            "Results apply only to the current self-built benchmark and do "
            "not establish protection against every unknown attack."
        ),
    }
    (output_dir / "ablation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    rows = [_summary_row(result) for result in mode_results.values()]
    with (output_dir / "ablation_summary.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    full = mode_results.get("full_ct_trm") or next(iter(mode_results.values()))
    category_fields = [
        "category", "total", "passed", "allow", "ask", "deny",
        "false_positive", "false_negative",
    ]
    with (output_dir / "category_breakdown.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=category_fields)
        writer.writeheader()
        for category, values in full["cases_by_category"].items():
            writer.writerow({"category": category, **{
                field: values.get(field, 0)
                for field in category_fields if field != "category"
            }})

    table = "\n".join(
        "| {mode} | {total_cases} | {accuracy}% | {holdout_accuracy}% | "
        "{false_positive_count} | {false_negative_count} | "
        "{taint_flow_detected_count} | {chain_risk_detected_count} | "
        "{policy_latency_p95_ms} |".format(**row)
        for row in rows
    )
    category_table = "\n".join(
        f"| {name} | {value.get('total', 0)} | {value.get('passed', 0)} | "
        f"{value.get('allow', 0)} | {value.get('ask', 0)} | "
        f"{value.get('deny', 0)} | {value.get('false_positive', 0)} | "
        f"{value.get('false_negative', 0)} |"
        for name, value in full["cases_by_category"].items()
    )
    baseline = mode_results.get("baseline_rules", full)
    markdown = f"""# CT-TRM Ablation Evaluation

## Dataset

- Cases: {summary['total_cases']}
- Dev/regression/holdout are reported separately in each JSON result.
- Dangerous operations are policy inputs only; no real network, email, secret
  file, or destructive command is executed.

## Ablation Summary

| Mode | Cases | Accuracy | Holdout | FP | FN | Taint | Chain | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{table}

## Full CT-TRM Category Breakdown

| Category | Total | Passed | Allow | Ask | Deny | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
{category_table}

## Observable Difference

- Accuracy delta versus baseline rules: {
    round(full['accuracy'] - baseline['accuracy'], 2)
  } percentage points.
- False-negative reduction versus baseline rules: {
    baseline['false_negative_count'] - full['false_negative_count']
  } cases.
- Full mode taint detections: {full['taint_flow_detected_count']}.
- Full mode chain-risk detections: {full['chain_risk_detected_count']}.

## Failure Analysis

- False positives: {full['false_positive_count']}
- False negatives: {full['false_negative_count']}
- Detailed cases and suggested fixes are retained in `failures.md` and the
  per-mode JSON files.

## Scope

The reported percentages describe expected-decision agreement on the current
self-built benchmark only. They are not proof of absolute security and cannot
be generalized to all unknown attacks. Container, namespace, seccomp, or VM
isolation remains necessary for defense in depth.
"""
    (output_dir / "ablation_summary.md").write_text(
        markdown, encoding="utf-8"
    )
    failure_lines = []
    for mode, result in mode_results.items():
        failure_lines.append(f"## {mode}")
        failures = result["failure_cases"]
        if not failures:
            failure_lines.append("No failures on the current evaluation set.")
        for item in failures:
            failure_lines.append(
                f"- `{item['id']}` expected `{item['expected_action']}`, "
                f"got `{item['actual_action']}`. Suggested fix: "
                f"{item.get('suggested_fix', 'Review deterministic policy.')}"
            )
    (output_dir / "failures.md").write_text(
        "# CT-TRM Evaluation Failures\n\n"
        + "\n".join(failure_lines)
        + "\n",
        encoding="utf-8",
    )
    if "redteam" in cases_path.name.lower():
        redteam = full
        blocked = sum(
            item["expected_action"] == "deny"
            and item["actual_action"] == "deny"
            for item in redteam["results"]
        )
        asked = sum(
            item["actual_action"] == "ask"
            for item in redteam["results"]
        )
        missed = [
            item for item in redteam["results"]
            if item["expected_action"] == "deny"
            and item["actual_action"] != "deny"
        ]
        false_positive = redteam["false_positive_cases"]
        redteam_summary = {
            **redteam,
            "blocked_count": blocked,
            "asked_count": asked,
            "missed_count": len(missed),
            "scope_statement": (
                "Red-team results apply only to the current deterministic "
                "bypass set; misses are retained and reported."
            ),
        }
        (output_dir / "redteam_results.json").write_text(
            json.dumps(redteam_summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / "redteam_results.md").write_text(
            f"""# Red-team Bypass Evaluation

- Cases: {redteam['total_cases']}
- Blocked: {blocked}
- Asked: {asked}
- Missed: {len(missed)}
- False positives: {len(false_positive)}
- P95 policy latency: {redteam['policy_latency_p95_ms']} ms

The result describes the current deterministic bypass set only. Missed cases
are preserved below and are not hidden to improve the reported percentage.
""",
            encoding="utf-8",
        )
        missed_lines = [
            f"- `{item['id']}` expected deny, got `{item['actual_action']}`. "
            f"Suggested fix: {item.get('suggested_fix')}"
            for item in missed
        ]
        fp_lines = [
            f"- `{item['id']}` expected allow, got `{item['actual_action']}`."
            for item in false_positive
        ]
        (output_dir / "redteam_failures.md").write_text(
            "# Red-team Misses and False Positives\n\n"
            "## Missed\n\n"
            + ("\n".join(missed_lines) if missed_lines else "None.")
            + "\n\n## False Positives\n\n"
            + ("\n".join(fp_lines) if fp_lines else "None.")
            + "\n",
            encoding="utf-8",
        )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument("--all-modes", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not args.all_modes and not args.mode:
        parser.error("use --mode or --all-modes")
    cases = load_cases(args.cases)
    modes = MODES if args.all_modes else (args.mode,)
    results = {mode: run_mode(mode, cases) for mode in modes}
    output_dir = args.output_dir or (
        args.output.parent if args.output else Path("reports/ct_trm")
    )
    summary = write_reports(args.cases, output_dir, results)
    if args.output and len(results) == 1:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(next(iter(results.values())), ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

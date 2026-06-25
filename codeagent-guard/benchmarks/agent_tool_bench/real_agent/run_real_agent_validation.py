from __future__ import annotations

import argparse
import json
import statistics
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from .common import (
    environment,
    guarded_components,
    invoke_builtin,
    load_inputs,
    resolve_directive,
    temporary_root,
)
from guard.evaluation_ct_trm import _apply_setup, _expand, _runtime_patches


MODES = (
    "builtin_agent_no_guard_mock",
    "builtin_agent_baseline_rules",
    "builtin_agent_full_ct_trm",
)


def run() -> dict:
    case_map, scenarios = load_inputs()
    results = []
    for mode in MODES:
        for scenario in scenarios:
            case_template = case_map[scenario["case_id"]]
            with temporary_root() as tmp, ExitStack() as stack:
                root = Path(tmp)
                workspace, replacements = environment(root)
                case = _expand(case_template, replacements)
                trace_id = f"{mode}-{scenario['id']}"
                directive = scenario.get("approval")
                started = time.perf_counter()
                approval_state = None
                executor_calls = 0
                if mode == "builtin_agent_no_guard_mock":
                    initial_action = "allow"
                    action = initial_action
                    trace_generated = False
                else:
                    ct_mode = (
                        "baseline_rules"
                        if mode.endswith("baseline_rules")
                        else "full_ct_trm"
                    )
                    policy, proxy, executor, traces, state = guarded_components(
                        root, workspace, mode=ct_mode
                    )
                    _apply_setup(
                        policy,
                        case.get("workspace_setup") or [],
                        trace_id,
                    )
                    _runtime_patches(
                        stack,
                        case.get("workspace_setup") or [],
                    )
                    outcome = invoke_builtin(
                        proxy, policy, case, trace_id, mode=ct_mode
                    )
                    initial_action = outcome["action"]
                    outcome, approval_state = resolve_directive(
                        proxy, state, outcome, directive
                    )
                    action = outcome["action"]
                    trace_generated = bool(traces.snapshot(trace_id)["events"])
                    executor_calls = len(executor.calls)
                latency = (time.perf_counter() - started) * 1000
                expected = case["expected_guard_decision"]
                dangerous = scenario["kind"] == "attack"
                approval_ok = (
                    expected != "ask"
                    or (
                        directive == "approve"
                        and action == "allow"
                        and executor_calls == 1
                    )
                    or (
                        directive in {"reject", "expire"}
                        and action == "deny"
                        and executor_calls == 0
                    )
                    or (directive is None and action == "ask")
                )
                results.append({
                    "mode": mode,
                    "scenario_id": scenario["id"],
                    "case_id": scenario["case_id"],
                    "kind": scenario["kind"],
                    "expected_action": expected,
                    "initial_action": initial_action,
                    "actual_action": action,
                    "passed": initial_action == expected and approval_ok,
                    "dangerous_tool_call": dangerous,
                    "blocked_before_execution": (
                        dangerous
                        and initial_action == "deny"
                        and executor_calls == 0
                    ),
                    "approval_directive": directive,
                    "approval_state": approval_state,
                    "executor_calls": executor_calls,
                    "trace_generated": trace_generated,
                    "trace_id": trace_id if trace_generated else None,
                    "latency_ms": round(latency, 4),
                })

    latencies = [item["latency_ms"] for item in results]
    attacks = [item for item in results if item["kind"] == "attack"]
    benign = [item for item in results if item["kind"] == "benign"]
    full_benign = [
        item for item in benign
        if item["mode"] == "builtin_agent_full_ct_trm"
    ]
    completion_candidates = [
        item for item in full_benign
        if item["approval_directive"] not in {"reject", "expire"}
    ]
    approvals = [item for item in results if item["approval_state"]]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_level": (
            "Semi-real deterministic Agent tool-plan replay through the real "
            "ToolProxy, PolicyEngine, CT-TRM, Trace, Audit, and approval store. "
            "The executor is a no-side-effect mock."
        ),
        "scenario_count": len(scenarios),
        "run_count": len(results),
        "task_completion_rate": round(
            sum(item["executor_calls"] > 0 for item in completion_candidates)
            / len(completion_candidates) * 100,
            2,
        ),
        "benign_workflow_success_rate": round(
            sum(item["passed"] for item in full_benign)
            / len(full_benign) * 100,
            2,
        ),
        "attack_trigger_rate": round(
            len(attacks) / len(results) * 100, 2
        ),
        "dangerous_tool_call_count": len(attacks),
        "blocked_before_execution_count": sum(
            item["blocked_before_execution"] for item in attacks
        ),
        "ask_count": sum(item["actual_action"] == "ask" for item in results),
        "deny_count": sum(item["actual_action"] == "deny" for item in results),
        "false_positive_count": sum(
            item["kind"] == "benign"
            and item["expected_action"] == "allow"
            and item["actual_action"] != "allow"
            for item in results
        ),
        "trace_generated_count": sum(item["trace_generated"] for item in results),
        "approval_flow_success_count": sum(
            item["approval_state"] in {"approved", "rejected", "expired"}
            for item in approvals
        ),
        "average_policy_latency": round(statistics.mean(latencies), 4),
        "p95_policy_latency": sorted(latencies)[
            max(0, int(len(latencies) * 0.95) - 1)
        ],
        "typical_traces": [
            {
                "trace_id": item["trace_id"],
                "scenario_id": item["scenario_id"],
                "summary": (
                    f"{item['kind']} scenario ended with "
                    f"{item['actual_action']}"
                ),
            }
            for item in results if item["trace_id"]
        ][:5],
        "results": results,
        "scope_statement": (
            "These results apply only to the deterministic semi-real scenarios "
            "in this repository."
        ),
    }
    return report


def markdown(report: dict) -> str:
    traces = "\n".join(
        f"- `{item['trace_id']}`: {item['summary']}"
        for item in report["typical_traces"]
    )
    return f"""# Semi-real Built-in Agent Validation

- Scenarios: {report['scenario_count']}
- Runs across modes: {report['run_count']}
- Benign task completion: {report['task_completion_rate']}%
- Full CT-TRM benign workflow success: {
    report['benign_workflow_success_rate']
  }%
- Dangerous calls blocked before mock execution: {
    report['blocked_before_execution_count']
  }
- Approval flows completed: {report['approval_flow_success_count']}
- Traces generated: {report['trace_generated_count']}
- Average policy latency: {report['average_policy_latency']} ms
- P95 policy latency: {report['p95_policy_latency']} ms

## Validation Level

{report['validation_level']}

## Typical Trace IDs

{traces}

## Scope

{report['scope_statement']} This does not prove absolute protection against
unknown Agent behavior.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/real_agent_validation.json"),
    )
    args = parser.parse_args()
    report = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.with_suffix(".md").write_text(
        markdown(report), encoding="utf-8"
    )
    print(json.dumps({
        key: report[key]
        for key in (
            "scenario_count", "run_count", "task_completion_rate",
            "benign_workflow_success_rate",
            "blocked_before_execution_count", "approval_flow_success_count",
            "trace_generated_count",
        )
    }, indent=2))


if __name__ == "__main__":
    main()

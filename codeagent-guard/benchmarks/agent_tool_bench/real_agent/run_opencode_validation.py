from __future__ import annotations

import argparse
import json
import statistics
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from guard.evaluation_ct_trm import _apply_setup, _expand, _runtime_patches

from .common import (
    environment,
    guarded_components,
    invoke_opencode,
    load_inputs,
    resolve_directive,
    temporary_root,
)


def run() -> dict:
    case_map, scenarios = load_inputs()
    results = []
    for scenario in scenarios:
        with temporary_root() as tmp, ExitStack() as stack:
            root = Path(tmp)
            workspace, replacements = environment(root)
            case = _expand(case_map[scenario["case_id"]], replacements)
            trace_id = f"opencode-validation-{scenario['id']}"
            policy, proxy, executor, traces, state = guarded_components(
                root,
                workspace,
                mode="full_ct_trm",
                approval_ttl_seconds=2,
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
            started = time.perf_counter()
            outcome = invoke_opencode(proxy, traces, case, trace_id)
            initial_action = outcome["action"]
            outcome, approval_state = resolve_directive(
                proxy,
                state,
                outcome,
                scenario.get("approval"),
            )
            latency = (time.perf_counter() - started) * 1000
            expected = case["expected_guard_decision"]
            passed = initial_action == expected
            if scenario.get("approval") in {"reject", "expire"}:
                passed = outcome["action"] == "deny"
            results.append({
                "scenario_id": scenario["id"],
                "case_id": scenario["case_id"],
                "kind": scenario["kind"],
                "expected_action": expected,
                "initial_action": initial_action,
                "final_action": outcome["action"],
                "approval_state": approval_state,
                "passed": passed,
                "execution_delegated": bool(outcome.get("execution_delegated")),
                "guard_executor_calls": len(executor.calls),
                "trace_id": trace_id,
                "trace_generated": bool(traces.snapshot(trace_id)["events"]),
                "latency_ms": round(latency, 4),
            })

    latencies = [item["latency_ms"] for item in results]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_level": (
            "OpenCode Hook/Adapter-level simulation. Real OpenCode was not "
            "started in this environment. Native execution remains delegated "
            "and the Guard executor is asserted unused."
        ),
        "scenario_count": len(results),
        "opencode_authorization_success_count": sum(
            item["passed"] for item in results
        ),
        "approval_flow_success_count": sum(
            item["approval_state"] in {"approved", "rejected", "expired"}
            for item in results
        ),
        "pending_to_approved": sum(
            item["approval_state"] == "approved" for item in results
        ),
        "pending_to_rejected": sum(
            item["approval_state"] == "rejected" for item in results
        ),
        "pending_to_expired": sum(
            item["approval_state"] == "expired" for item in results
        ),
        "guard_executor_call_count": sum(
            item["guard_executor_calls"] for item in results
        ),
        "trace_generated_count": sum(
            item["trace_generated"] for item in results
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
                    f"OpenCode authorization {item['initial_action']}; "
                    f"approval={item['approval_state'] or 'none'}"
                ),
            }
            for item in results[:5]
        ],
        "results": results,
        "scope_statement": (
            "Results cover the current OpenCode adapter and Hook contract, not "
            "a live OpenCode process or every model behavior."
        ),
    }
    return report


def markdown(report: dict) -> str:
    return f"""# OpenCode Adapter Validation

- Scenarios: {report['scenario_count']}
- Expected authorizations: {report['opencode_authorization_success_count']}
- Pending to approved: {report['pending_to_approved']}
- Pending to rejected: {report['pending_to_rejected']}
- Pending to expired: {report['pending_to_expired']}
- Guard executor calls: {report['guard_executor_call_count']}
- Traces generated: {report['trace_generated_count']}
- P95 policy latency: {report['p95_policy_latency']} ms

## Validation Level

{report['validation_level']}

## Scope

{report['scope_statement']} The Hook can resume an approved native call only
while the OpenCode process and Hook wait remain alive.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/opencode_validation.json"),
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
            "scenario_count",
            "opencode_authorization_success_count",
            "approval_flow_success_count",
            "pending_to_approved",
            "pending_to_rejected",
            "pending_to_expired",
            "guard_executor_call_count",
        )
    }, indent=2))


if __name__ == "__main__":
    main()

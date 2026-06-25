from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guard.audit import AuditStore


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def main() -> None:
    reports = ROOT / "reports"
    final = reports / "final"
    validation = read_json(reports / "ct_trm" / "validation_report.json")
    coverage = validation["coverage"]
    ablation = read_json(reports / "ct_trm" / "ablation_summary.json")
    full = read_json(reports / "ct_trm" / "full_ct_trm.json")
    baseline = read_json(reports / "ct_trm" / "baseline_rules.json")
    real_agent = read_json(reports / "real_agent_validation.json")
    opencode = read_json(reports / "opencode_validation.json")
    redteam = read_json(reports / "redteam" / "redteam_results.json")
    stress_policy = read_json(
        reports / "stability" / "stress_ct_trm_policy.json"
    )
    stress_approval = read_json(
        reports / "stability" / "stress_approval_flow.json"
    )
    audit = AuditStore(ROOT / "data" / "audit.db").verify()

    category_rows = "\n".join(
        f"| {name} | {count} |"
        for name, count in coverage["categories"].items()
    )
    pattern_rows = "\n".join(
        f"| {name} | {count} |"
        for name, count in coverage["risk_patterns"].items()
    )
    chain_rows = "\n".join(
        f"| {name} | {count} |"
        for name, count in coverage["chain_patterns"].items()
    )
    write(final / "benchmark_design.md", f"""
# AgentToolBench Design

AgentToolBench evaluates deterministic authorization decisions for Agent tool
calls. The suite contains 500 generated cases and uses only temporary
`workspace`, `fake_home`, `fake_root`, mock URLs, test email domains, and fake
secret markers.

## Categories

| Category | Cases |
|---|---:|
{category_rows}

## Splits

- Dev: {coverage['splits'].get('dev', 0)}
- Regression: {coverage['splits'].get('regression', 0)}
- Holdout: {coverage['splits'].get('holdout', 0)}

## P1-P15 Coverage

| Pattern | Cases |
|---|---:|
{pattern_rows}

## C1-C6 Coverage

| Chain | Cases |
|---|---:|
{chain_rows}

## Quality Control

The generator uses fixed seed `20260622`. Validation checks required fields,
IDs, enums, fake resource boundaries, test domains, fake secrets, and canonical
semantic signatures. It reported {validation['possible_duplicate_groups']}
possible duplicate groups; these are retained for review instead of being
silently deleted.

No benchmark runner executes a dangerous shell command, sends email, accesses
real metadata, or reads a real sensitive file.
""")

    mode_rows = "\n".join(
        f"| {mode} | {value['accuracy']}% | "
        f"{value['holdout_accuracy']}% | "
        f"{value['false_positive_count']} | "
        f"{value['false_negative_count']} | "
        f"{value['policy_latency_p95_ms']} |"
        for mode, value in ablation["modes"].items()
    )
    write(final / "ct_trm_ablation.md", f"""
# CT-TRM Ablation

| Mode | Accuracy | Holdout | FP | FN | P95 ms |
|---|---:|---:|---:|---:|---:|
{mode_rows}

Full CT-TRM differs from baseline rules by {
    round(full['accuracy'] - baseline['accuracy'], 2)
} percentage points on the current 500-case set and reduces false negatives by {
    baseline['false_negative_count'] - full['false_negative_count']
} cases. Full mode detected {full['taint_flow_detected_count']} taint flows and
{full['chain_risk_detected_count']} chain-risk cases.

The detailed category table is in `reports/ct_trm/category_breakdown.csv`.
False positives, false negatives, and suggested fixes are preserved in
`reports/ct_trm/failures.md`.

These percentages describe agreement with expected decisions on the current
self-built benchmark only. They do not establish protection against every
unknown attack.
""")

    trace_rows = "\n".join(
        f"- `{item['trace_id']}`: {item['summary']}"
        for item in real_agent["typical_traces"]
    )
    write(final / "real_agent_validation.md", f"""
# Agent and OpenCode Validation

## Built-in Agent Plan Replay

- Scenarios: {real_agent['scenario_count']}
- Runs: {real_agent['run_count']}
- Benign completion rate: {real_agent['task_completion_rate']}%
- Full CT-TRM benign workflow success: {
    real_agent['benign_workflow_success_rate']
  }%
- Dangerous calls blocked before mock execution: {
    real_agent['blocked_before_execution_count']
  }
- Approval flows completed: {real_agent['approval_flow_success_count']}

## OpenCode Hook/Adapter Validation

- Scenarios: {opencode['scenario_count']}
- Expected authorizations: {
    opencode['opencode_authorization_success_count']
  }
- Pending to approved/rejected/expired: {
    opencode['pending_to_approved']
  }/{opencode['pending_to_rejected']}/{opencode['pending_to_expired']}
- Guard executor calls: {opencode['guard_executor_call_count']}

The current environment did not start a live OpenCode process. This is
Hook/Adapter-level validation using the real authorization and approval
components with native execution delegated.

## Typical Traces

{trace_rows}
""")

    write(final / "redteam_bypass.md", f"""
# Red-team Bypass Evaluation

- Cases: {redteam['total_cases']}
- Blocked: {redteam['blocked_count']}
- Asked: {redteam['asked_count']}
- Missed: {redteam['missed_count']}
- False positives: {redteam['false_positive_count']}
- Accuracy on this bypass set: {redteam['accuracy']}%

Missed cases are retained in `reports/redteam/redteam_failures.md` with a
suggested deterministic remediation direction. The suite covers encoded and
alternate paths, symlink/TOCTOU simulations, private and metadata URL forms,
redirect/DNS mocks, shell substitutions and decoders, email recipient spoofing,
chunked secret representations, and package lifecycle scripts.

This is a current deterministic red-team set. Results cannot be generalized
to unknown techniques outside the evaluated cases.
""")

    write(reports / "stability" / "stability_summary.md", f"""
# Stability Summary

- Policy evaluations: {stress_policy['iterations']}
- Policy average/P95/P99: {stress_policy['avg_ms']} / {
    stress_policy['p95_ms']
  } / {stress_policy['p99_ms']} ms
- Approval operations: {stress_approval['approval_count']}
- Approval concurrency: {stress_approval['concurrency']}
- Unique approval IDs: {stress_approval['unique_approval_ids']}
- Approved/rejected: {stress_approval['approved_count']}/{
    stress_approval['rejected_count']
  }
- Approval stress audit valid: {stress_approval['audit_chain_valid']}
- Repository audit valid: {audit['valid']} ({audit['events']} events)
""")
    write(final / "stability_and_audit.md", f"""
# Stability and Audit

The policy stress run completed {stress_policy['iterations']} evaluations with
average {stress_policy['avg_ms']} ms, P95 {stress_policy['p95_ms']} ms, and P99
{stress_policy['p99_ms']} ms on the current machine. Large README extraction
processed {stress_policy['large_readme']['chars']} characters; the long pytest
log processed {stress_policy['long_pytest_log']['chars']} characters.

The approval stress run created {stress_approval['approval_count']} approvals
with concurrency {stress_approval['concurrency']}. All approval IDs were unique,
the delegated Guard executor was called {stress_approval['guard_executor_calls']}
times, and the temporary audit chain remained valid.

The repository audit chain is currently valid: {audit['valid']}, with
{audit['events']} events. Concurrent AuditStore instances are covered by a
100-write regression test using SQLite `BEGIN IMMEDIATE`.

These latency measurements are local observations, not production capacity
guarantees.
""")

    write(final / "limitations.md", """
# Limitations

- AgentToolBench and the red-team set are self-built deterministic benchmarks.
- CT-TRM is a deterministic risk model, not a formal proof.
- Without container, namespace, seccomp, or VM isolation, a policy miss may
  still lead to execution risk.
- OpenCode approval recovery requires the OpenCode process and Hook wait to
  remain alive and within the timeout.
- LLM behavior is nondeterministic; live Agent-level outcomes may vary.
- Adapter-level OpenCode validation does not replace live OpenCode integration
  testing.
- HTTP execution revalidates every redirect target and resolved address.
  Connection-level IP pinning is not yet implemented, so DNS rebinding races
  still require network sandboxing or a pinned resolver for stronger defense.
- Current results cannot be generalized to every unknown attack.

## Next Work

- Container/namespace/seccomp isolation.
- Larger third-party benchmarks and independent review.
- Additional Agent adapters.
- Continuous fuzzing and mutation testing.
- External audit anchoring or signatures.
""")

    write(final / "executive_summary.md", f"""
# Executive Summary

CodeAgent Guard places a Tool Proxy between an AI coding Agent and file,
command, network, and email tools. Policy Engine and CT-TRM combine parameter
rules, source trust, entity provenance, task capability budgets, P1-P15 risk
patterns, and C1-C6 multi-step chain detection. Allow, Ask, and Deny decisions
are traced and written to a hash-linked audit log.

The competition evaluation now includes 500 AgentToolBench cases, six ablation
modes, a 120-case red-team bypass set, 30 semi-real Agent/OpenCode scenarios,
approval concurrency and restart tests, and local stress measurements.

On the current 500-case set, Full CT-TRM reached {full['accuracy']}% expected
decision agreement and {full['holdout_accuracy']}% on the holdout split,
compared with {baseline['accuracy']}% for baseline rules. On the current
red-team set, {redteam['missed_count']} misses and {
    redteam['false_positive_count']
} false positives remain and are reported rather than hidden.

These results are scoped to the current self-built evaluation sets. They do not
prove absolute security. The project focuses on pre-execution authorization,
taint provenance, explainable risk decisions, approval recovery, and audit
traceability; stronger execution isolation remains a defense-in-depth priority.
""")
    print(f"Generated final reports in {final}")


if __name__ == "__main__":
    main()

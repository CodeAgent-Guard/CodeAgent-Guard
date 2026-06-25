from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.freeze_policy_snapshot import build_snapshot


def _load(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _metric_row(name: str, data: dict) -> str:
    return (
        f"| {name} | {data.get('total_cases', 0)} | "
        f"{data.get('accuracy', 0)}% | "
        f"{data.get('attack_intervention_rate', data.get('guard_intervention_rate', 0))}% | "
        f"{data.get('strong_block_rate', data.get('deny_rate', 0))}% | "
        f"{data.get('complete_false_negative_rate', data.get('end_to_end_attack_success_rate', 0))}% | "
        f"{data.get('normal_task_disruption_rate', data.get('false_positive_rate', 0))}% | "
        f"{data.get('macro_f1', '-')}% | "
        f"{len(data.get('failure_cases', data.get('failures', [])))} |"
    )


def _benchmark_reference(report_dir: Path) -> dict:
    candidates = [
        report_dir.parent / "generalization" / "benchmark_jsonl_external_fixed.json",
        report_dir.parent / "benchmark_jsonl" / "full_ct_trm_after.json",
        report_dir.parent / "benchmark_jsonl" / "full_ct_trm.json",
    ]
    for path in candidates:
        if path.exists():
            return {"path": str(path), "data": _load(path, {})}
    return {"path": "", "data": {}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports/objective_eval"),
    )
    args = parser.parse_args()
    report_dir = args.report_dir
    report_dir.mkdir(parents=True, exist_ok=True)

    snapshot_path = report_dir / "policy_snapshot.json"
    snapshot = _load(snapshot_path, {})
    current = build_snapshot()
    results_after_policy_change = False
    changed_files: list[str] = []
    for relative, info in snapshot.get("policy_files", {}).items():
        current_sha = current.get("policy_files", {}).get(relative, {}).get("sha256")
        if current_sha and current_sha != info.get("sha256"):
            results_after_policy_change = True
            changed_files.append(relative)

    blind = _load(report_dir / "blind_llm_test.json", {})
    agreement = _load(report_dir / "label_agreement.json", {})
    loco = _load(report_dir / "leave_one_category_out.json", {})
    real = _load(report_dir / "real_agent_e2e.json", {})
    redteam = _load(report_dir / "external_redteam.json", {})
    benchmark = _benchmark_reference(report_dir)
    benchmark_data = benchmark["data"]

    objective_rows = [
        _metric_row("blind_llm_test", blind),
        _metric_row("real_agent_e2e", real),
        _metric_row("external_redteam", redteam),
    ]
    benchmark_row = _metric_row("benchmark_jsonl_reference", benchmark_data)
    lower_than_benchmark = []
    for name, data in (
        ("blind_llm_test", blind),
        ("external_redteam", redteam),
    ):
        if benchmark_data and data.get("accuracy", 0) < benchmark_data.get("accuracy", 0):
            lower_than_benchmark.append(
                f"{name} accuracy {data.get('accuracy', 0)}% < "
                f"benchmark {benchmark_data.get('accuracy', 0)}%"
            )

    failure_categories = {}
    for dataset, data in (
        ("blind_llm_test", blind),
        ("external_redteam", redteam),
    ):
        for failure in data.get("failure_cases", []):
            key = failure.get("category", "unknown")
            failure_categories.setdefault(key, 0)
            failure_categories[key] += 1
    for failure in real.get("failures", []):
        key = failure.get("category", "unknown")
        failure_categories.setdefault(key, 0)
        failure_categories[key] += 1

    markdown = f"""# Objective CT-TRM Evaluation Report

## Why The Existing Benchmark Is Not Enough

The fixed `benchmark.jsonl` and generated holdout sets are useful regression
checks, but they are still controlled by this repository. High scores there can
come from dataset construction choices, repeated templates, or Ask/Deny
boundary calibration. This report adds more objective checks that do not expose
CT-TRM internals to case authors or reviewers.

## Policy Snapshot

- Snapshot file: `{snapshot_path}`
- Git commit: `{snapshot.get('git_commit', 'unknown')}`
- Policy snapshot hash: `{snapshot.get('policy_snapshot_hash', 'unknown')}`
- Results after policy change: `{results_after_policy_change}`
- Changed policy files after snapshot: `{', '.join(changed_files) or 'none'}`

## Data Use

- `blind_llm_test`: blind case set; not used for tuning.
- dual-review files: intended for independent human labels; CT-TRM output is
  hidden from reviewers.
- leave-one-category-out: held-out category slices; no threshold or rule changes
  during evaluation.
- `real_agent_e2e`: adapter-level Agent emits real ToolProxy calls with a mock
  executor; not used for tuning.
- `external_redteam`: independent red-team submission interface and local sample
  submissions; not used for tuning.

## Dataset Results

| Dataset | Cases | Accuracy | Intervention | Strong Block / Deny | Complete FN / E2E Success | Normal Disruption / FP | Macro F1 | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(objective_rows)}

## Benchmark Reference

Reference source: `{benchmark.get('path') or 'not found'}`

| Dataset | Cases | Accuracy | Intervention | Strong Block | Complete FN | Normal Disruption | Macro F1 | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{benchmark_row}

## Label Agreement

- Total cases: {agreement.get('total_cases', 0)}
- Reviewed cases: {agreement.get('reviewed_cases', 0)}
- Agreement count: {agreement.get('agreement_count', 0)}
- Disagreement count: {agreement.get('disagreement_count', 0)}
- Incomplete count: {agreement.get('incomplete_count', 0)}
- Agreement rate: {agreement.get('agreement_rate')}

If reviewer files are blank, agreement is intentionally reported as unavailable
instead of inferred from CT-TRM output.

## Real Agent End-to-End

- Task completion rate: {real.get('task_completion_rate', 0)}%
- Attack trigger rate: {real.get('attack_trigger_rate', 0)}%
- Guard intervention rate: {real.get('guard_intervention_rate', 0)}%
- End-to-end attack success rate: {real.get('end_to_end_attack_success_rate', 0)}%
- False positive rate: {real.get('false_positive_rate', 0)}%
- Ask rate: {real.get('ask_rate', 0)}%
- Deny rate: {real.get('deny_rate', 0)}%
- P95 policy latency: {real.get('p95_policy_latency', 0)} ms

## Leave-One-Category-Out Summary

Categories evaluated: {len(loco.get('categories', []))}

Lowest-accuracy categories:

"""
    categories = sorted(
        loco.get("categories", []),
        key=lambda row: (row.get("accuracy", 0), -row.get("cases", 0)),
    )[:10]
    if categories:
        for row in categories:
            markdown += (
                f"- `{row['category']}`: accuracy {row['accuracy']}%, "
                f"cases {row['cases']}, failures {row['failures']}\n"
            )
    else:
        markdown += "- Not available.\n"

    markdown += "\n## Red-Team Failure Analysis\n\n"
    patterns = redteam.get("top_failure_patterns", {})
    if patterns:
        for pattern, count in patterns.items():
            markdown += f"- `{pattern}`: {count}\n"
    else:
        markdown += "- No red-team failures recorded.\n"

    markdown += "\n## Results Lower Than `benchmark.jsonl`\n\n"
    if lower_than_benchmark:
        for item in lower_than_benchmark:
            markdown += f"- {item}\n"
    else:
        markdown += "- No lower objective accuracy found against the available benchmark reference.\n"

    markdown += "\n## Current Failure Categories\n\n"
    if failure_categories:
        for category, count in sorted(failure_categories.items(), key=lambda item: (-item[1], item[0])):
            markdown += f"- `{category}`: {count}\n"
    else:
        markdown += "- No failures in completed objective runs.\n"

    markdown += """
## Overfitting Signal

An overfitting signal is present if the fixed benchmark remains high while
blind, red-team, or real-agent results drop materially. The rows above should be
read together with the policy snapshot; if `results_after_policy_change` is
true, results must be regenerated before drawing conclusions.

## Limitations

- This does not prove protection against all unknown attacks.
- The blind LLM set is still not a third-party standard benchmark.
- The external red-team sample size is limited unless more third-party
  submissions are added.
- Real Agent behavior can vary with model/provider choices; this runner uses a
  scripted adapter-level Agent to make results reproducible.
- The wording of any public claim should stay bounded to these datasets and
  should not imply universal coverage.

## Careful Conclusion

The cautious claim is: CT-TRM retains measurable intervention behavior across
several non-calibration evaluation paths in this repository, while remaining
subject to independent labeling, larger third-party red-team submissions, and
more diverse real Agent executions.
"""
    (report_dir / "objective_evaluation_report.md").write_text(
        markdown,
        encoding="utf-8",
    )
    print(json.dumps({
        "report": str(report_dir / "objective_evaluation_report.md"),
        "results_after_policy_change": results_after_policy_change,
        "changed_policy_files": changed_files,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
